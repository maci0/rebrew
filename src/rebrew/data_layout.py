"""data_layout.py — shared .data/.bss placement model for byte-identity builds.

The linked ``.data`` section is the concatenation of per-TU contributions in
link order.  For the layout to converge to the original (byte-identity), the
raw region must be filled byte-exact and the BSS tail must reach the
reference's VirtualSize.  This module provides the shared machinery used by
``rebrew data layout audit`` and ``rebrew data layout fill`` (and
``rebrew build check-data-placement``):

- ``link_objects`` — the link's object files in link order (objects*.rsp);
- ``obj_data_symbols`` — a TU's .data/.bss size + owned symbol offsets;
- ``data_symbols`` — the .data symbol map from ``rebrew-data.toml``;
- ``owner_of`` — the most-referencing TU for a set of symbols;
- ``fill_data`` / ``insert_definition`` — write ``_dpad_<addr>[N]`` pads into
  an owning TU's source.

All addresses are full image VAs; the section geometry (``data_base``,
``raw_end``, ``section_end``) comes from the layout package
(``layout/<target>/rebrew-layout.toml``), so nothing is hardcoded per project.
"""

from __future__ import annotations

import functools
import logging
import re
from collections import defaultdict
from threading import Lock
lazy import io
lazy import math
lazy import struct
lazy from collections.abc import Iterator, Sequence
lazy from pathlib import Path
lazy from typing import Any

from rebrew.c_parser import CALLING_CONVENTION  # noqa: F401
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.formats.coff import load_coff
lazy from rebrew.metadata.data import iter_data_symbols, load_data_document
lazy from rebrew.sources import files_with_ext
lazy from rebrew.utils import atomic_write_text as atomic_write_text
lazy from rebrew.utils import (
    fold_ident,
    join_source_lines,
    load_tomllib,
    parse_c_integer_literal,
    preset_module_key,
    read_source_text,
    split_source_lines,
)
lazy from rebrew.workspace.config import config_path


def scan_files(src_dir: Path, shared_dir: Path | None = None) -> list[Path]:
    """``*.c`` files under *src_dir* plus the shared tree (deduplicated).

    DATA bindings in ``src/shared`` belong to every target; a ``reversed_dir``
    -only scan misses them (data layout fill never pads them, data layout own
    never owns them).  A ``None`` or missing *shared_dir* scans only *src_dir*.
    """
    files = files_with_ext(src_dir, {".c"})
    if shared_dir is not None:
        try:
            is_same = shared_dir.resolve() == src_dir.resolve()
        except OSError:
            is_same = False
        if not is_same and shared_dir.is_dir():
            seen = {p.resolve() for p in files}
            files.extend(p for p in files_with_ext(shared_dir, {".c"}) if p.resolve() not in seen)
    return files


# ---------------------------------------------------------------------------
# Link order + per-TU symbol inventory (objdump-based)
# ---------------------------------------------------------------------------

_OBJ_RE = re.compile(r'"([^"]+\.obj)"|(?:^|\s)(\S+\.obj)(?=\s|$)')
_LINK_OUTPUT_RE = re.compile(
    r'(?<!\S)(?:"/out:([^"]+)"|(?:/out:|-o[ \t]+)(?:"([^"]+)"|([^"\s]+)))(?=\s|$)',
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")
_INDENT_RE = re.compile(r"[ \t]*")
_CMAKE_DIR_RE = re.compile(r"^.*?CMakeFiles/[^/]+\.dir/")
_EXTERN_WORD_RE = re.compile(r"\bextern\b\s*")
_EXTERN_AT_START_RE = re.compile(r"extern\b")
_INIT_RE = re.compile(r"=\s*(\{[^;]*\}|[^;]+);?$")
_ARRAY_SIZE_RE = re.compile(r"\[(\d+)\]")
_NON_WORD_RE = re.compile(r"\W")
_C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|__int64")
_PAD_INSERT_RE = re.compile(r"(\n)(?=\s*(?:extern|static|__declspec|(?://|/\*) ADDRESS:))")


#: How many offending paths a fix_ownership error or rollback-failure message
#: names before it stops listing; a tree-wide permission problem would
#: otherwise print one line per source file.
_UNREADABLE_REPORT_LIMIT = 10

_logger = logging.getLogger(__name__)


def link_objects(root: Path, target: str | None = None) -> list[Path]:
    """The build's object files in link order.

    A build directory that holds several targets needs *target* (the linked
    file name, e.g. ``game.exe``); the ``/out:<target>`` line in each
    ``link.txt`` then picks that target's rsp directory instead of the first by
    name, which silently read another target's objects.  CMake builds are read
    from ``build/CMakeFiles/*/objects*.rsp``, which preserves the link order.
    Makefile-style builds (no rsp) fall back to
    the object directory (``out/`` then ``build/``) sorted by name — GNU
    make expands ``$(wildcard ...)``/``$(SRCS)`` in sorted order, so a plain
    Makefile links objects in exactly that order.
    """
    objects = _cmake_rsp_objects(root / "build", target)
    if objects is not None:
        return objects
    for obj_dir in ("out", "build"):
        obj_path = root / obj_dir
        if not obj_path.is_dir():
            continue
        objs = sorted(p for p in obj_path.iterdir() if p.is_file() and p.suffix in (".obj", ".o"))
        if objs:
            return objs
    raise FileNotFoundError(
        "no build/CMakeFiles/*/objects*.rsp or out|build/*.obj found — build the project first"
    )


def _cmake_rsp_objects(build_dir: Path, target: str | None = None) -> list[Path] | None:
    """Objects from a CMake build's ``objects*.rsp`` in link order.

    ``build_dir`` is the CMake binary directory (the one holding
    ``CMakeFiles/``).  Returns ``None`` when that directory has no rsp files, so
    a Makefile-style tree can fall back to scanning its object directory.
    """
    rsp_dirs = sorted({path.parent for path in (build_dir / "CMakeFiles").glob("*/objects*.rsp")})
    if not rsp_dirs:
        return None
    chosen = rsp_dirs[0]
    if target:
        wanted = fold_ident(config_path(target).name)
        matches = []
        for candidate in rsp_dirs:
            link_txt = candidate / "link.txt"
            if not link_txt.is_file():
                continue
            command = link_txt.read_text(encoding="utf-8", errors="replace")
            outputs = {
                fold_ident(config_path(a or b or c).name)
                for a, b, c in _LINK_OUTPUT_RE.findall(command)
            }
            if wanted in outputs:
                matches.append(candidate)
        if len(matches) != 1:
            detail = "ambiguous" if matches else "unresolved"
            raise ValueError(f"{detail} CMake link output for {target!r}")
        chosen = matches[0]
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="surrogateescape")
        for path in sorted(chosen.glob("objects*.rsp"))
    )
    # Wine/MSVC CMake rsp lines may use ``\\`` separators; on POSIX that
    # would become a single literal path component without normalization.
    return [build_dir / config_path(a or b) for a, b in _OBJ_RE.findall(text)]


def link_objects_in(build_dir: Path, target: str | None = None) -> list[Path]:
    """Objects of a build tree whose CMake binary directory is not ``build/``."""
    objects = _cmake_rsp_objects(build_dir, target)
    if objects is None:
        raise FileNotFoundError(f"no CMakeFiles/*/objects*.rsp under {build_dir}")
    return objects


def _parse_obj_sections_and_symbols(
    obj: Path,
) -> tuple[dict[int, str], dict[str, int], tuple[tuple[int, int, str], ...]]:
    """Parse section sizes and symbol table from a COFF or ELF object via LIEF."""
    try:
        raw = obj.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read object file {obj}: {exc}") from exc

    if raw[:4] == b"\x7fELF":
        import lief

        elf = lief.ELF.parse(io.BytesIO(raw))
        if elf is None:
            raise RuntimeError(f"failed to parse ELF object {obj}")
        secname: dict[int, str] = {}
        sizes: dict[str, int] = {}
        for idx, sec in enumerate(elf.sections):
            name = str(sec.name)
            secname[idx] = name
            if name:
                sizes[name] = sizes.get(name, 0) + int(sec.size)
        rows = tuple(
            (int(sym.shndx) + 1, int(sym.value), str(sym.name))
            for sym in elf.symbols
            if sym.name and sym.shndx > 0
        )
        return secname, sizes, rows

    loaded = load_coff(raw)
    if loaded is None:
        raise RuntimeError(f"failed to parse COFF object {obj}")
    coff, symbols, names = loaded
    secname = {}
    sizes = {}
    for idx, coff_sec in enumerate(coff.sections):
        name = str(coff_sec.name).rstrip("\x00")
        secname[idx] = name
        # COFF .bss carries its size in SizeOfRawData with PointerToRawData == 0.
        sec_size = max(int(coff_sec.sizeof_raw_data), int(coff_sec.virtual_size))
        sizes[name] = sizes.get(name, 0) + sec_size
    rows = tuple(
        (int(sym.section_idx), int(sym.value), sym_name)
        for sym, sym_name in zip(symbols, names, strict=True)
        if sym.section_idx > 0 and sym_name
    )
    return secname, sizes, rows


_OBJ_TABLE_CACHE: dict[
    tuple[str, int, int, int, int],
    tuple[dict[int, str], dict[str, int], tuple[tuple[int, int, str], ...]],
] = {}
_OBJ_TABLE_LOCK = Lock()


def _obj_table(
    obj: Path,
) -> tuple[dict[int, str], dict[str, int], tuple[tuple[int, int, str], ...]]:
    """Stat-cached ``(secname, sizes, symbol_rows)`` parsed once via LIEF."""
    try:
        st = obj.stat()
        key = (str(obj), st.st_mtime_ns, st.st_size, st.st_ino, st.st_ctime_ns)
    except OSError:
        return _parse_obj_sections_and_symbols(obj)
    with _OBJ_TABLE_LOCK:
        hit = _OBJ_TABLE_CACHE.get(key)
        if hit is not None:
            return hit
    parsed = _parse_obj_sections_and_symbols(obj)
    with _OBJ_TABLE_LOCK:
        if len(_OBJ_TABLE_CACHE) >= 1024:
            _OBJ_TABLE_CACHE.clear()
        _OBJ_TABLE_CACHE[key] = parsed
    return parsed


def obj_data_symbols(obj: Path) -> tuple[int, int, set[str], set[str]]:
    """``(dsize, bsize, .data symbols, .bss symbols)`` of one object file."""
    sizes, buckets = obj_section_symbols(obj, ".data", ".bss")
    return sizes[".data"], sizes[".bss"], buckets[".data"], buckets[".bss"]


def obj_section_symbols(obj: Path, *sections: str) -> tuple[dict[str, int], dict[str, set[str]]]:
    """``({section: size}, {section: symbols})`` of one object file.

    Generalization of :func:`obj_data_symbols` for extra sections (``.rdata``).
    Only the requested sections are inventoried. Each symbol is the C name:
    ``__g_foo`` stays ``_g_foo`` and ``hook@@12`` is ``hook``.
    """
    from rebrew.rename_ops import c_name_from_symbol

    secname, sizes, rows = _obj_table(obj)
    buckets: dict[str, set[str]] = {s: set() for s in sections}
    for sec_idx, _value, raw_sym in rows:
        bare = raw_sym.lstrip("_")
        if not bare or bare.startswith((".", "@")):
            continue
        sname = secname.get(sec_idx - 1)
        if sname in buckets:
            buckets[sname].add(c_name_from_symbol(raw_sym))
    return {s: sizes.get(s, 0) for s in sections}, buckets


def obj_data_symbol_offsets(obj: Path) -> tuple[int, dict[str, int]]:
    """(obj .data size, {symbol: offset within the obj's .data}).

    The key is the C name. ``__g_foo`` is ``_g_foo`` and ``hook@@12`` is
    ``hook``; ``lstrip("_")`` stored both underscore symbols as ``g_foo``.
    """
    from rebrew.rename_ops import c_name_from_symbol

    secname, sizes, rows = _obj_table(obj)
    dsize = sizes.get(".data", 0)
    syms: dict[str, int] = {}
    for sec_idx, value, raw_sym in rows:
        bare = raw_sym.lstrip("_")
        if not bare or bare.startswith((".", "@")):
            continue
        if secname.get(sec_idx - 1) == ".data":
            syms[c_name_from_symbol(raw_sym)] = value
    return dsize, syms


def obj_text_symbol_offsets(obj: Path) -> tuple[int, dict[str, int]]:
    """(obj .text size, {symbol: offset within the obj's .text}).

    The key is the C name. ``__foo`` is ``_foo`` and ``hook@@12`` is
    ``hook``; ``lstrip("_")`` stored both ``__foo`` and ``_foo`` as ``foo``.
    Same shape as :func:`obj_data_symbol_offsets`, for the ``.text`` side —
    the primitive ``rebrew build check-text-placement`` walks per TU in link order.
    """
    from rebrew.rename_ops import c_name_from_symbol

    secname, sizes, rows = _obj_table(obj)
    syms: dict[str, int] = {}
    for sec_idx, value, raw_sym in rows:
        bare = raw_sym.lstrip("_")
        if not bare or bare.startswith((".", "@")):
            continue
        if secname.get(sec_idx - 1) == ".text":
            syms[c_name_from_symbol(raw_sym)] = value
    return sizes.get(".text", 0), syms


# ---------------------------------------------------------------------------
# Data metadata + layout geometry
# ---------------------------------------------------------------------------


def data_symbols(
    metadata: Path,
    section: str | Sequence[str] | None = ".data",
    module: str | None = None,
) -> dict[str, int]:
    """``{name: full VA}`` for every symbol in *section* of the metadata.

    *module* keeps one target's rows.  A project that holds several binaries
    stores each binary's address for the same name; without the filter the
    last row wins, which is usually another target's.

    *section* is one name, a set of names, or ``None`` for every section.  The
    default (``.data``) is the historical contract; callers that model the
    section tail pass ``(".data", ".bss")`` — BSS globals carry
    ``section=".bss"`` (``rebrew data set --type`` / the Ghidra import), so a
    ``.data``-only read silently drops them.
    """
    db = load_data_document(metadata)
    wanted = None if section is None else {section} if isinstance(section, str) else set(section)
    return {
        str(val["name"]): va
        for row_module, va, val in iter_data_symbols(db, None)
        if val.get("name")
        and (wanted is None or val.get("section") in wanted)
        and (module is None or preset_module_key(row_module) == preset_module_key(module))
    }


def layout_geometry(project_toml: Path, target: str | None = None) -> tuple[int, int, int]:
    """``(data_base, raw_end, section_end)`` full-VA from the layout package.

    *target* selects the ``layout/<target>/`` package; without it the
    project's ``default_target`` is used, falling back to the first
    ``layout/*/`` package present.  *project_toml* locates the project
    root (its parent dir).  The old code read ``[targets.*.layout]`` from
    the TOML itself and always took the FIRST target, so a multi-target
    project sized ``data layout converge``'s pads against another binary's
    geometry.
    """
    from rebrew.layout_meta import read_layout_geometry

    root = project_toml.parent
    if target:
        return read_layout_geometry(root, target)

    cfg = load_tomllib(project_toml)
    default = str(cfg.get("project", {}).get("default_target") or "")
    if default and (root / "layout" / default / "rebrew-layout.toml").exists():
        return read_layout_geometry(root, default)
    pkgs = (
        sorted((root / "layout").glob("*/rebrew-layout.toml")) if (root / "layout").is_dir() else []
    )
    if pkgs:
        return read_layout_geometry(root, pkgs[0].parent.name)
    raise ValueError(f"no layout package under {root / 'layout'} (run rebrew build layout first)")


def data_raw_from_binary(bin_path: Path) -> bytes:
    """The reference's raw .data bytes."""
    info = load_binary(bin_path)
    sec = info.sections.get(".data")
    if sec is None:
        raise ValueError("no .data section in the reference binary")
    return info.data[sec.file_offset : sec.file_offset + sec.raw_size]


def data_section_base(bin_path: Path) -> int | None:
    """The reference binary's .data section VA, or None without one.

    Same loader and section as :func:`data_raw_from_binary`, so the base and
    the raw bytes it indexes always describe the same selected binary even
    when the project layout package belongs to another target.
    """
    sec = load_binary(bin_path).sections.get(".data")
    return sec.va if sec is not None else None


def data_raw_size(bin_path: Path) -> int | None:
    """The reference binary's .data raw size, or None without the section."""
    sec = load_binary(bin_path).sections.get(".data")
    return sec.raw_size if sec is not None else None


def data_byte_order(bin_path: Path) -> str:
    """The reference's ``struct`` byte-order prefix (``">"`` for big-endian targets)."""
    return ">" if load_binary(bin_path).endian == "big" else "<"


# ---------------------------------------------------------------------------
# Ownership + source edits
# ---------------------------------------------------------------------------

#: Word-only identifier test for :func:`owner_of` fast lookup.
#: ``$`` and other non-word symbols stay on the alternation scan below.
_WORD_NAME_RE = re.compile(r"\w+\Z")
#: Bounded cache for the multi-name alternation fallback in ``owner_of``;
#: the same name set is queried once per ownership pass.
_OWNER_PAT_CACHE_MAX = 64


@functools.lru_cache(maxsize=_OWNER_PAT_CACHE_MAX)
def _owner_pat(names_key: tuple[str, ...]) -> re.Pattern[str]:
    """Whole-word alternation for *names_key*; cached per name set."""
    return re.compile(r"\b(?:" + "|".join(re.escape(n) for n in names_key) + r")\b")


def _read_sources_or_fail(files: list[Path]) -> list[tuple[Path, str]]:
    """``(path, text)`` for every file, or ``OSError`` naming the unreadable ones.

    A skipped TU looks unowned, so its globals get emitted into another unit
    while the skipped file keeps the definitions: duplicate globals at link
    time, from a run that reports edits and moved counts.  Every ownership
    scan therefore fails on the whole set rather than dropping files.
    """
    texts: list[tuple[Path, str]] = []
    unreadable: list[Path] = []
    for f in files:
        try:
            text, _encoding = read_source_text(f)
        except OSError:
            unreadable.append(f)
            continue
        texts.append((f, text))
    if unreadable:
        raise OSError(
            "cannot read "
            f"{len(unreadable)} of {len(files)} source files, so global ownership "
            "cannot be determined: "
            + ", ".join(str(p) for p in unreadable[:_UNREADABLE_REPORT_LIMIT])
            + ("..." if len(unreadable) > _UNREADABLE_REPORT_LIMIT else "")
        )
    return texts


def reference_counts(files: list[Path]) -> list[tuple[Path, dict[str, int]]]:
    """AST identifier reference counts for each readable file, in *files* order.

    ``fill_data`` and ``own_data_globals`` ask for an owner once per symbol.
    Counting ``tree-sitter-c`` ``identifier`` nodes once answers every later
    owner query while ignoring comments and string literals.
    """
    from rebrew.c_parser import mask_msvc_syntax, node_text, parse_c_source

    indexed: list[tuple[Path, dict[str, int]]] = []
    for f, text in _read_sources_or_fail(files):
        tree, data = parse_c_source(mask_msvc_syntax(text))
        counts: dict[str, int] = {}
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            kind = node.type
            if kind in ("comment", "string_literal", "char_literal"):
                continue
            if kind == "identifier":
                word = node_text(node, data)
                counts[word] = counts.get(word, 0) + 1
            else:
                stack.extend(node.named_children)
        if counts:
            indexed.append((f, counts))
    return indexed


def _owner_from_references(
    names: list[str], references: list[tuple[Path, dict[str, int]]]
) -> Path | None:
    """First file whose whole-word hits of *names* are strictly the most."""
    wanted = set(names)
    best: Path | None = None
    best_n = 0
    for path, counts in references:
        n = sum(counts.get(name, 0) for name in wanted)
        if n > best_n:
            best = path
            best_n = n
    return best


def owner_of(
    names: list[str],
    files: list[Path],
    references: list[tuple[Path, dict[str, int]]] | None = None,
) -> Path | None:
    """The most-referencing file over *names* (None when nothing references them).

    *references* is a :func:`reference_counts` table for *files*.  It is used
    when every name is one word (``\\w+``): that count matches ``\\bname\\b``,
    including a name that is a prefix of another.  A repeated name is counted
    once, as in the alternation.  Any other name (a ``$`` in the symbol) falls
    back to a fresh scan so the match is unchanged.
    """
    if not names:
        return None
    if references is not None and all(_WORD_NAME_RE.fullmatch(name) for name in names):
        return _owner_from_references(names, references)
    # One alternation instead of N separate compiles × findall passes.
    pat = _owner_pat(tuple(names))
    counts: dict[Path, int] = defaultdict(int)
    for f, t in _read_sources_or_fail(files):
        n = len(pat.findall(t))
        if n:
            counts[f] = n
    if not counts:
        return None
    return max(counts, key=lambda p: counts[p])


def hex_list(data: bytes) -> str:
    """A C array-initializer body for *data* (16 bytes per line, comma-separated)."""
    out = []
    for i in range(0, len(data), 16):
        out.append("    " + ", ".join(f"0x{b:02x}" for b in data[i : i + 16]) + ",")
    return "{\n" + "\n".join(out) + "\n}"


_FILE_SCOPE_CONTAINERS = frozenset(
    {"translation_unit", "preproc_if", "preproc_ifdef", "preproc_else", "preproc_elif"}
)


def _byte_to_char(text: str, raw: bytes, byte_offset: int) -> int:
    """Convert a UTF-8/surrogateescape byte offset in *raw* to a character index in *text*."""
    if len(raw) == len(text):
        return byte_offset
    return len(raw[:byte_offset].decode("utf-8", errors="surrogateescape"))


def _line_indent_start(text: str, char_start: int) -> int:
    """Walk back from *char_start* over leading spaces/tabs on the same line."""
    pos = char_start
    while pos > 0 and text[pos - 1] in (" ", "\t"):
        pos -= 1
    return pos


def _iter_file_scope_decls(text: str) -> Iterator[tuple[Any, bytes]]:
    """Yield ``(declaration_node, raw_bytes)`` for every file-scope declaration in *text*."""
    from rebrew.c_parser import mask_msvc_syntax, parse_c_source

    masked = mask_msvc_syntax(text)
    tree, _masked_bytes = parse_c_source(masked)
    raw = text.encode("utf-8", errors="surrogateescape")
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        kind = node.type
        if kind == "declaration" and not node.has_error:
            yield node, raw
            continue
        if kind in _FILE_SCOPE_CONTAINERS:
            stack.extend(reversed(node.named_children))


def _array_bracket_text(node: Any, raw: bytes) -> str:
    """Return the ``[...]`` slice of an ``array_declarator`` node."""
    start: int | None = None
    end: int | None = None
    for child in node.children:
        if child.type == "[" and start is None:
            start = int(child.start_byte)
        elif child.type == "]" and start is not None:
            end = int(child.end_byte)
    if start is None or end is None:
        return ""
    return raw[start:end].decode("utf-8", errors="surrogateescape")


def _analyze_var_declarator(declarator: Any, raw: bytes) -> tuple[str, bool, str, str] | None:
    """Analyze a non-function variable declarator.

    Returns ``(name, is_pointer_to_array, own_brackets, pointer_prefix)`` or
    ``None`` when *declarator* is a plain function prototype or has no name.

    - ``is_pointer_to_array`` is True for ``(*name)[N]`` / ``(**name)[N]`` where
      the brackets sit outside the parentheses on the pointee.
    - ``own_brackets`` is the object's own dimension suffix (e.g. ``[0x10]``,
      ``[2][4]``, ``[2]`` for ``(*table[2])[3]``).
    - ``pointer_prefix`` is the raw pointer/convention/qualifier slice before
      the identifier when the declarator wraps a pointer around an array
      (e.g. ``*``, ``** const``, ``__cdecl *``).
    """
    from rebrew.c_parser import declares_function, node_text

    if declarator.type == "init_declarator":
        declarator = declarator.child_by_field_name("declarator")
    if declarator is None or declares_function(declarator):
        return None

    # Check if there is a parenthesized_declarator in the declarator chain.
    outer_array_count = 0
    found_paren: Any = None
    probe = declarator
    while probe is not None:
        if probe.type == "parenthesized_declarator":
            found_paren = probe
            break
        if probe.type == "array_declarator":
            outer_array_count += 1
            probe = probe.child_by_field_name("declarator")
        elif probe.type in ("function_declarator", "pointer_declarator"):
            probe = probe.child_by_field_name("declarator")
        else:
            break

    inner_target = declarator
    if found_paren is not None:
        inner_children = [c for c in found_paren.named_children if c.type != "comment"]
        if len(inner_children) != 1:
            return None
        inner_target = inner_children[0]

    has_ptr = False
    cur = inner_target
    while cur is not None and cur.type == "pointer_declarator":
        has_ptr = True
        cur = cur.child_by_field_name("declarator")

    bracket_parts: list[str] = []
    while cur is not None and cur.type == "array_declarator":
        bracket_parts.append(_array_bracket_text(cur, raw))
        cur = cur.child_by_field_name("declarator")

    if cur is None or cur.type != "identifier":
        return None

    name = node_text(cur, raw)
    bracket_parts.reverse()
    own_brackets = "".join(bracket_parts)

    is_ptr_to_array = (
        found_paren is not None and has_ptr and not own_brackets and outer_array_count > 0
    )

    pointer_prefix = ""
    if has_ptr and own_brackets:
        # Raw text from inside '(' (or start of pointer_declarator) up to the identifier.
        if found_paren is not None:
            open_byte = int(found_paren.start_byte)
            # Skip '(' itself.
            if open_byte < len(raw) and raw[open_byte : open_byte + 1] == b"(":
                open_byte += 1
            prefix_raw = raw[open_byte : int(cur.start_byte)].decode(
                "utf-8", errors="surrogateescape"
            )
        else:
            prefix_raw = raw[int(inner_target.start_byte) : int(cur.start_byte)].decode(
                "utf-8", errors="surrogateescape"
            )
        pointer_prefix = _WS_RE.sub(" ", prefix_raw).strip()

    return name, is_ptr_to_array, own_brackets, pointer_prefix


def _decl_has_extern(decl_node: Any, raw: bytes) -> bool:
    from rebrew.c_parser import node_text

    return any(
        c.type == "storage_class_specifier" and node_text(c, raw) == "extern"
        for c in decl_node.named_children
    )


def _find_matching_decl_span(
    text: str, name: str, *, is_array: bool, extern: bool
) -> tuple[int, int] | None:
    """Find ``(start_char, end_char)`` of a file-scope non-initialized decl of *name*."""
    if name not in text:
        return None
    for decl_node, raw in _iter_file_scope_decls(text):
        if _decl_has_extern(decl_node, raw) != extern:
            continue
        declarators = decl_node.children_by_field_name("declarator")
        if len(declarators) != 1:
            continue
        child = declarators[0]
        if child.type == "init_declarator":
            continue
        analyzed = _analyze_var_declarator(child, raw)
        if analyzed is None:
            continue
        var_name, is_ptr_to_arr, own_brackets, _ptr_prefix = analyzed
        if var_name != name:
            continue
        has_brackets = bool(own_brackets) or is_ptr_to_arr
        if has_brackets != is_array:
            continue
        start = _line_indent_start(text, _byte_to_char(text, raw, int(decl_node.start_byte)))
        end = _byte_to_char(text, raw, int(decl_node.end_byte))
        return start, end
    return None


def _declared_base_types(text: str, name: str) -> set[str]:
    """Base C types used for *name* in declarations this TU already holds.

    The caller skips a symbol whose existing declarations disagree instead of
    emitting a second type for it: two definitions of one name with different
    types collide (C2371) in the rebuilt TU.
    """
    from rebrew.c_parser import node_text

    if name not in text:
        return set()
    found: set[str] = set()
    for decl_node, raw in _iter_file_scope_decls(text):
        for child in decl_node.children_by_field_name("declarator"):
            analyzed = _analyze_var_declarator(child, raw)
            if analyzed is None or analyzed[0] != name:
                continue
            type_parts = [
                node_text(c, raw)
                for c in decl_node.named_children
                if c.type
                in (
                    "type_qualifier",
                    "primitive_type",
                    "sized_type_specifier",
                    "type_identifier",
                    "struct_specifier",
                    "enum_specifier",
                    "union_specifier",
                )
            ]
            base = _WS_RE.sub(" ", " ".join(type_parts)).strip()
            if base:
                found.add(base)
    return found


def insert_definition(
    f: Path,
    name: str,
    ctype: str,
    size: int,
    init_text: str | None,
    dry_run: bool,
    is_array: bool = True,
    *,
    array_suffix: str = "",
) -> bool:
    """Define ``ctype name = init;`` / ``ctype name[size] = init;`` in *f*.

    Replaces an existing matching ``extern`` declaration in place (keeping its
    indentation); replaces an existing definition of *name* in place so a
    re-run does not append a duplicate; appends only when the TU has neither.
    With ``is_array=False`` a scalar ``TYPE name = value;`` is emitted.
    """
    # Preserve legacy source encodings (Shift-JIS / CP1252): reading as UTF-8
    # with errors="replace" and writing UTF-8 permanently corrupts non-ASCII
    # comments/strings (e.g. Japanese game TUs). Same convention as
    # annotation / climb / rename write-backs.
    text, encoding = read_source_text(f)
    if dry_run and name not in text:
        return True
    suffix = (array_suffix or f"[{size}]") if is_array else ""
    def_line = f"{ctype} {name}{suffix}"
    if init_text:
        def_line += f" = {init_text}"
    def_line += ";"

    extern_span = _find_matching_decl_span(text, name, is_array=is_array, extern=True)
    if extern_span is not None:
        start, end = extern_span
        indent_m = _INDENT_RE.match(text[start:])
        indent = indent_m.group(0) if indent_m else ""
        replacement = indent + def_line
        if text[start:end] != replacement and not dry_run:
            atomic_write_text(f, text[:start] + replacement + text[end:], encoding=encoding)
        return True

    # Idempotent re-run: an existing definition (with initializer) must be
    # replaced in place — appending would leave two definitions of *name*.
    found = _find_definition(text, name)
    if found is not None:
        start, end, _typ, _sz = found
        indent_m = _INDENT_RE.match(text[start:])
        indent = indent_m.group(0) if indent_m else ""
        replacement = indent + def_line
        if text[start:end] == replacement:
            return True
        new_text = text[:start] + replacement + text[end:]
        if not dry_run:
            atomic_write_text(f, new_text, encoding=encoding)
        return True

    # No-init pads / tentative defs (``unsigned char _dpad_N[K];``) are not
    # matched by ``_find_definition`` (it requires ``=``) — replace those too.
    existing_span = _find_matching_decl_span(text, name, is_array=is_array, extern=False)
    if existing_span is not None:
        start, end = existing_span
        indent_m = _INDENT_RE.match(text[start:])
        indent = indent_m.group(0) if indent_m else ""
        replacement = indent + def_line
        if text[start:end] != replacement and not dry_run:
            atomic_write_text(f, text[:start] + replacement + text[end:], encoding=encoding)
        return True

    lines = split_source_lines(text)
    lines.append(def_line)
    if not dry_run:
        atomic_write_text(f, join_source_lines(text, lines), encoding=encoding)
    return True


# ---------------------------------------------------------------------------
# layout-audit
# ---------------------------------------------------------------------------


def audit_layout(
    root: Path, metadata: Path, section: str = ".data", target: str | None = None
) -> dict[str, Any]:
    """Per-TU span/order feasibility report for *section* (``.data`` or ``.rdata``).

    Returns rows (per TU: symbol count, min/max addr, section sizes, flags),
    the violation count, and the unowned/duplicate-owned symbol lists.
    ``.bss`` symbols ride along for ordering context in ``.data`` mode only.
    """
    build_target: str | None
    if (root / "rebrew-project.toml").is_file():
        build_target = _converge_target(root, target)
        module = _target_module(root, build_target)
    else:
        build_target = target
        module = None
    toml = data_symbols(metadata, section, module=module)
    owner: dict[str, list[str]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    violations = 0
    extra = (".bss",) if section == ".data" else ()
    for obj in link_objects(root, build_target):
        name = str(obj).split(".dir/")[-1]
        try:
            sizes, buckets = obj_section_symbols(obj, section, *extra)
        except RuntimeError as exc:
            # Record the broken TU and keep auditing the rest — a visible
            # OBJDUMP_ERROR row beats both a crash and silent zero sizes.
            rows.append(
                {
                    "obj": name,
                    "dsize": 0,
                    "bsize": 0,
                    "dsyms": [],
                    "bsyms": [],
                    "min_addr": 0,
                    "max_addr": 0,
                    "flags": ["OBJDUMP_ERROR"],
                    "error": str(exc),
                }
            )
            violations += 1
            continue
        syms = buckets.get(section, set())
        bsyms = buckets.get(".bss", set()) if extra else set()
        rows.append(
            {
                "obj": name,
                "dsize": sizes.get(section, 0),
                "bsize": sizes.get(".bss", 0) if extra else 0,
                "dsyms": sorted(syms),
                "bsyms": sorted(bsyms),
            }
        )
        for sym in syms | bsyms:
            if sym in toml:
                owner[sym].append(name)

    prev_max: int | None = None
    for r in rows:
        if "error" in r:
            continue  # already flagged — nothing to order/score
        all_syms: set[str] = set(r["dsyms"]) | set(r["bsyms"])
        vas = sorted(toml[s] for s in all_syms if s in toml)
        lo = vas[0] if vas else 0
        hi = vas[-1] if vas else 0
        flags: list[str] = []
        if vas and prev_max is not None and lo < prev_max:
            flags.append("ORDER")
            violations += 1
        if vas and hi - lo > 0x4000:
            flags.append("SPAN")
            violations += 1
        r["min_addr"] = lo
        r["max_addr"] = hi
        r["flags"] = flags
        if hi:
            prev_max = max(prev_max or 0, hi)

    unowned = sorted((s for s in toml if s not in owner), key=lambda s: toml[s])
    dup = {s: fs for s, fs in owner.items() if len(fs) > 1}
    return {
        "rows": rows,
        "violations": violations,
        "unowned": [(s, toml[s]) for s in unowned],
        "duplicate_owned": sorted(((s, toml[s], fs) for s, fs in dup.items()), key=lambda t: t[1]),
    }


# ---------------------------------------------------------------------------
# fill-data (byte-exact raw region + BSS sizing)
# ---------------------------------------------------------------------------


_PAD_DECL_RE = re.compile(r"unsigned char (_dpad_[0-9a-f]+)\s*\[")


def _existing_pad_names(files: Sequence[Path]) -> set[str]:
    """Names of pads this tree already declares, in any owner TU.

    A pad is identified by its address, not by its current owner: when the
    most-referencing TU changes between runs, re-emitting the pad would declare
    one address twice with different sizes in two files.
    """
    names: set[str] = set()
    for path in files:
        try:
            text, _encoding = read_source_text(path)
        except OSError:
            continue
        names.update(_PAD_DECL_RE.findall(text))
    return names


def fill_data(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    dry_run: bool = False,
    bss_only: bool = False,
    target: str | None = None,
    shared_dir: Path | None = None,
) -> dict[str, int]:
    """Emit ``_dpad_<addr>[N]`` pads for the uncovered .data byte runs.

    Initialized-region gaps (below the raw end) are filled byte-exact from
    the reference binary; BSS gaps (beyond the raw end, to the section VS)
    become zero-init pads.  The owner TU of each pad is the most-referencing
    file of the following symbol (leading run: the first symbol's owner).
    Returns ``{"init_pads": n, "bss_pads": n}``.

    *target* selects which ``[targets.*]`` geometry the pads are sized
    against; without it the project default applies (a multi-target project
    otherwise placed pads against another binary's ``.data``).
    *shared_dir* adds the shared tree to the owner scan (DATA bindings in
    ``src/shared`` belong to every target).
    """
    data_base, raw_end, section_end = layout_geometry(root / "rebrew-project.toml", target=target)
    orig = data_raw_from_binary(bin_path)
    module = _target_module(root, _converge_target(root, target))
    module_key = preset_module_key(module) if module is not None else None
    arch = load_binary(bin_path).arch
    by_addr = sorted(
        (va, str(fields["name"]), data_symbol_size(fields, arch=arch))
        for row_module, va, fields in iter_data_symbols(load_data_document(metadata), None)
        if fields.get("name")
        and fields.get("section") in (".data", ".bss")
        and (module_key is None or preset_module_key(row_module) == module_key)
        and va < section_end
    )
    if not by_addr:
        return {"init_pads": 0, "bss_pads": 0}
    files = scan_files(src_dir, shared_dir)
    references = reference_counts(files)
    known_pads = _existing_pad_names(files)

    def emit_pad(owner: Path, name: str, size: int, init: str | None) -> bool:
        if name in known_pads:
            return False
        if insert_definition(owner, name, "unsigned char", size, init, dry_run):
            known_pads.add(name)
            return True
        return False

    n_bss = n_pad = 0

    start = data_base
    previous = ""
    for addr, name, size in [*by_addr, (section_end, "", 0)]:
        if addr > start and (addr - start > 0x40 if previous else addr < raw_end):
            neighbors = [item for item in (previous, name) if item]
            owner = owner_of(neighbors, files, references)
            if owner is not None:
                raw_stop = min(addr, raw_end)
                if not bss_only and raw_stop > start:
                    data = orig[start - data_base : raw_stop - data_base]
                    if len(data) == raw_stop - start and emit_pad(
                        owner, f"_dpad_{start:x}", len(data), hex_list(data)
                    ):
                        n_pad += 1
                bss_start = max(start, raw_end)
                if addr > bss_start and emit_pad(
                    owner, f"_dpad_{bss_start:x}", addr - bss_start, None
                ):
                    n_bss += 1
        # An unbounded allocation may extend over later rows. Keep the rest
        # of the section unmodified until the missing extent is recorded.
        stop = min(addr + size, section_end) if size else section_end
        if stop > start:
            start = stop
            previous = name
    return {"init_pads": n_pad, "bss_pads": n_bss}


# ---------------------------------------------------------------------------
# data layout own: materialize stub-file globals as real definitions
# ---------------------------------------------------------------------------

# One nested pair inside a bound. Stopping at the first ``]`` dropped
# ``char g[sizeof(wchar_t[3])] = {0};`` from the stub inventory.
_STUB_DEF_RE = re.compile(
    r"^\s*([\w\s\*]+?)\s+(\w+)"
    r"((?:\[(?:[^\[\]]|\[[^\]]*\])*\])*)"
    r"\s*=\s*(?:\{[^;]*\}|[^;]+);\s*$"
)


def _parse_stub_globals(stub_file: Path) -> dict[str, tuple[str, int | None, str]]:
    """Base type, element count, and retained multidimensional suffix of each stub."""
    from rebrew.c_parser import array_type_shape

    out: dict[str, tuple[str, int | None, str]] = {}
    text, _ = read_source_text(stub_file)
    for line in split_source_lines(text):
        m = _STUB_DEF_RE.match(line)
        if not m:
            continue
        typ = " ".join(m.group(1).split())
        if typ == "extern":
            continue
        brackets = m.group(3)
        _, dimensions = array_type_shape(f"char _{brackets}") if brackets else ("", ())
        count = _element_count_or_none(dimensions)
        # A declarator whose bounds are not all constants (``g[]``, ``g[N]``)
        # has no element count.  Storing None would materialize it as a scalar.
        if brackets and count is None:
            continue
        out[m.group(2)] = (typ, count, brackets if len(dimensions) > 1 else "")
    return out


#: Byte sizes for the C base types that appear in stub files and data
#: metadata (32-bit target: pointers and ``long`` are 4).  The single
#: authoritative table — data.py's coverage estimator sizes through it too,
#: so the two size models cannot drift apart again.
_TYPE_SIZES: dict[str, int] = {
    "char": 1,
    "unsigned char": 1,
    "signed char": 1,
    "bool": 1,
    "BYTE": 1,
    "BOOLEAN": 1,
    "short": 2,
    "short int": 2,
    "unsigned short": 2,
    "unsigned short int": 2,
    "signed short": 2,
    "signed short int": 2,
    "wchar_t": 2,
    "WORD": 2,
    "int": 4,
    "unsigned int": 4,
    "signed int": 4,
    "long": 4,
    "long int": 4,
    "unsigned long": 4,
    "unsigned long int": 4,
    "signed long int": 4,
    "BOOL": 4,  # Windef.h: typedef int BOOL
    "DWORD": 4,
    "LONG": 4,
    "ULONG": 4,
    "float": 4,
    "FLOAT": 4,
    "double": 8,
    "DOUBLE": 8,
    "__int64": 8,
    "unsigned __int64": 8,
    "LONGLONG": 8,
    "long long": 8,
    "signed long long": 8,
    "unsigned long long": 8,
    "long long int": 8,
    "signed long long int": 8,
    "unsigned long long int": 8,
}

_ARRAY_SUFFIX_RE = re.compile(r"\[\s*((?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*)\s*\]")


def _bound_value(bound: int | str | None) -> int | None:
    """One array dimension as a nonnegative count, or None when it is not constant."""
    if isinstance(bound, int):
        value = bound
    elif isinstance(bound, str):
        try:
            value = parse_c_integer_literal(bound)
        except ValueError:
            return None
    else:
        return None
    return value if value >= 0 else None


def _element_count_or_none(dimensions: Sequence[int | str | None]) -> int | None:
    """Element count of a C array declarator, or None when there are no bounds.

    Every ``[N]`` counts: ``[2][4]`` is 8 elements, not 2.  ``010`` is octal
    (8).  A complete constant expression (``[2 + 2]``, ``[0x300 * 0x21c]``)
    folds the same way :func:`estimate_type_size` does.  A bound that is not
    a constant (``[N]``) leaves the count unknown.
    """
    if not dimensions:
        return None
    total = 1
    for bound in dimensions:
        n = _bound_value(bound)
        if n is None:
            return None
        # ``T[0]`` is a flexible-array extension; count it as one element, the
        # same rule estimate_type_size applies, so the two size models agree
        # and no symbol reaches the layout with a zero size.
        if n == 0:
            n = 1
        total *= n
    return total


#: Largest extent :func:`estimate_type_size` will report. A declared bound
#: whose product exceeds the 32-bit address space is not a global this
#: toolchain can place, and treating it as one inflates coverage.
_MAX_ESTIMATED_BYTES = 0xFFFFFFFF


#: Words that are not part of a declared type: storage classes and
#: qualifiers precede it, the declared name follows it.
_NON_TYPE_WORDS = frozenset({"extern", "static", "auto", "register", "const", "volatile", "signed"})

#: Multi-word type spellings that survive qualifier/name stripping below.
_TYPE_PHRASES = frozenset(
    {
        "unsigned char",
        "signed char",
        "unsigned short",
        "signed short",
        "unsigned int",
        "signed int",
        "unsigned long",
        "long",
        "long long",
        "unsigned long long",
        "signed long long",
        "unsigned __int64",
    }
)


def c_type_size(ctype: str) -> int:
    """Byte size of a C type on the 32-bit target (pointers are 4)."""
    if "*" in ctype:
        return 4
    # Strip the declared name (trailing identifier) and any [] suffix, then
    # drop storage-class/qualifier words: `extern short g_s;` -> `short`.
    # A bare trailing word with no type before it (`g_thing;`) is unknown.
    text = _ARRAY_SUFFIX_RE.sub("", ctype).strip().rstrip(";").strip()
    words = _C_IDENT_RE.findall(text)
    while words and words[0] in _NON_TYPE_WORDS:
        words.pop(0)
    while words and words[-1] not in _TYPE_SIZES and " ".join(words[-2:]) not in _TYPE_PHRASES:
        words.pop()
    if not words:
        return 4
    for width in (4, 3, 2, 1):
        if len(words) >= width and " ".join(words[-width:]) in _TYPE_SIZES:
            return _TYPE_SIZES[" ".join(words[-width:])]
    return 4


def data_symbol_size(fields: dict[str, Any], *, arch: str = "x86_32") -> int:
    """Known symbol extent from SIZE or a supported fixed-size declaration.

    An invalid explicit SIZE stays unknown rather than being truncated or
    replaced by an estimate. Unresolved bounds, structs, and unknown typedefs
    need explicit SIZE; a guessed prefix cannot prove the complete symbol.
    Zero is an unspecified size. Type inference uses the existing x86_32
    model; other architectures need explicit SIZE.
    """
    from rebrew.c_parser import (
        abstract_pointer_array_dimensions,
        array_type_shape,
        is_pointer_to_array,
    )
    from rebrew.metadata.functions import as_metadata_int

    try:
        size = as_metadata_int(fields.get("size", 0))
    except TypeError, ValueError:
        return 0
    if size < 0:
        return 0
    if size:
        return size
    if arch != "x86_32":
        return 0
    type_str = fields.get("type")
    if not isinstance(type_str, str) or not type_str:
        return 0
    # ``T (*)[N]`` is one pointer. Parentheses must not hide the extent, and
    # reading ``[N]`` as a dimension would make it N pointers.
    # A ``(*)`` inside the bound, as in ``int[sizeof(char (*)[4])]``, is not
    # this symbol's declarator.
    if is_pointer_to_array(type_str):
        return 4
    # ``T (*[N])`` is N pointers. The brackets sit inside the parentheses, so
    # the plain array shape would report the extent as unknown instead of N * 4.
    abstract = abstract_pointer_array_dimensions(type_str)
    if abstract is not None:
        width = 4
        for bound in abstract:
            if not isinstance(bound, int) or bound <= 0:
                return 0
            width *= bound
        return width
    base, dimensions = array_type_shape(type_str)
    if "[" in type_str and not dimensions:
        return 0
    # ``T (*name[N])[M]`` shapes as N pointers to ``T (*)[M]``. The
    # parentheses are the element, not an unknown type. A function
    # pointer (``void (*)(int)``) has no array dimension and stays
    # unknown.
    if is_pointer_to_array(base):
        width = 4
        for bound in dimensions:
            if not isinstance(bound, int) or bound <= 0:
                return 0
            width *= bound
            if width > _MAX_ESTIMATED_BYTES:
                return 0
        return width
    base = " ".join(word for word in base.split() if word not in _NON_TYPE_WORDS)
    if "(" in base or ")" in base:
        return 0
    # ponytail: existing 32-bit type model; other ABIs need explicit SIZE.
    width = 4 if base.endswith("*") else _TYPE_SIZES.get(base, 0)
    for bound in dimensions:
        if not isinstance(bound, int) or bound <= 0:
            return 0
        width *= bound
        if width > _MAX_ESTIMATED_BYTES:
            return 0
    return width


#: Distinct declared type spellings kept by :func:`estimate_type_size`.
_TYPE_SIZE_CACHE_ENTRIES = 4096


@functools.lru_cache(maxsize=_TYPE_SIZE_CACHE_ENTRIES)
def estimate_type_size(type_str: str) -> int:
    """Byte size of a declared C type string (pointer- and array-aware).

    Memoized per spelling: a project repeats a few hundred type strings across
    thousands of globals, and each parse folds array bounds through tree-sitter.
    """
    from rebrew.c_parser import (
        abstract_pointer_array_dimensions,
        array_type_shape,
        is_pointer_to_array,
    )

    text = type_str.rstrip().rstrip(";").strip()
    # ``T (*)[N]`` and ``T (**)[N]`` are one pointer. The bracket names the
    # array that pointer addresses. Reading it as a dimension sized
    # ``char (*)[4]`` as 16. ``T *[N]`` has no ``(*)`` and stays an array.
    # A ``(*)`` inside the bound is not this object's declarator.
    if is_pointer_to_array(text):
        return 4
    # ``T (*[N])`` and ``T (*[N])(params)`` are N pointers. The brackets
    # sit inside the parentheses, so reading only the pointer would report one.
    abstract = abstract_pointer_array_dimensions(text)
    if abstract:
        count = 1
        for bound in abstract:
            if isinstance(bound, int) and bound > 0:
                count *= bound
                # Past the 32-bit address space the product is not a size a
                # global can have; 0 means unknown, matching an unresolvable
                # bound, instead of a multi-gigabyte coverage contribution.
                if count > _MAX_ESTIMATED_BYTES // 4:
                    return 0
        return 4 * count
    base, dimensions = array_type_shape(text)
    count = 1
    for bound in dimensions:
        if isinstance(bound, int) and bound > 0:
            count *= bound
            if count > _MAX_ESTIMATED_BYTES:
                return 0
    size = c_type_size(base) * count
    return size if size <= _MAX_ESTIMATED_BYTES else 0


def typed_array_literal(ctype: str, data: bytes, byte_order: str = "<") -> tuple[str, int]:
    """C initializer text + element count for *data* read as *ctype* elements.

    Byte-sized elements keep :func:`hex_list`'s raw-byte layout; wider
    elements are formatted per element so ``int arr[3]`` emits three ints
    instead of twelve bytes under an inflated dimension.  *byte_order* is the
    target's ``struct`` prefix (:func:`data_byte_order`).

    Raises ``ValueError`` when an element has no valid C89 literal
    (a non-finite float/double — ``nan``/``inf`` are not constant
    expressions), so callers can skip the symbol instead of emitting a
    definition that cannot compile.
    """
    elemsize = c_type_size(ctype)
    if elemsize <= 1:
        return hex_list(data), len(data)
    usable = len(data) - len(data) % elemsize
    elems = []
    for off in range(0, usable, elemsize):
        lit = _scalar_literal(data[off : off + elemsize], ctype, elemsize, byte_order)
        if lit is None:
            raise ValueError(
                f"{ctype} element at byte {off} has no C89 literal (non-finite float/double bytes)"
            )
        elems.append(lit)
    lines = ["    " + ", ".join(elems[i : i + 16]) + "," for i in range(0, len(elems), 16)]
    return "{\n" + "\n".join(lines) + "\n}", len(elems)


def _scalar_literal(data: bytes, ctype: str, size: int, byte_order: str = "<") -> str | None:
    """A C initializer for *data* as *ctype* (None when the bytes don't fit).

    Floats and doubles (including the ``FLOAT``/``DOUBLE`` Windows typedefs)
    emit decimal literals whose widened-double repr round-trips to the exact
    original bits under any conforming compiler.  Non-finite values return
    None: C89 has no NaN/Inf literal, and an integer fallback would be
    implicitly converted to a completely different value.
    """
    if "*" in ctype:
        if len(data) >= 4:
            v = struct.unpack_from(byte_order + "I", data)[0]
            return "0" if v == 0 else f"(void*) 0x{v:08x}"
        return None
    base = ctype.rstrip("*").strip().lower()
    if base == "float":
        if len(data) < 4:
            return None
        v = struct.unpack_from(byte_order + "f", data)[0]
        return f"{v!r}f" if math.isfinite(v) else None
    if base == "double":
        if len(data) < 8:
            return None
        v = struct.unpack_from(byte_order + "d", data)[0]
        return repr(v) if math.isfinite(v) else None
    if len(data) < size:
        return None
    if size == 1:
        return str(data[0])
    if size == 2:
        return str(struct.unpack_from(byte_order + "H", data)[0])
    if size == 4:
        v = struct.unpack_from(byte_order + "I", data)[0]
        return f"0x{v:08x}" if v >= 0x10000000 else str(v)
    if size == 8:
        v = struct.unpack_from(byte_order + "Q", data)[0]
        return f"0x{v:016x}" if v else "0"
    return None


def own_data_globals(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    stub_file: Path,
    dry_run: bool = False,
    target: str | None = None,
    shared_dir: Path | None = None,
) -> dict[str, Any]:
    """Materialize stub-file globals as real definitions in their owner TUs.

    For every .data symbol in the data metadata that is still defined only as
    a placeholder in *stub_file* (e.g. ``src/link_stubs.c``), read the
    original bytes from *bin_path* and turn the owner TU's ``extern`` into a
    real definition — ``TYPE name = value;`` for scalars, ``TYPE name[N] =
    {...};`` for arrays — so the global is defined once, in the TU whose
    .data slot lands at the original address (link-order placement).
    Char arrays are NUL-terminated; other arrays use the declared element
    count, else the gap to the next metadata symbol (capped at the raw end).

    *stub_file*'s symbols then drop out of the unresolved set on regeneration
    (``rebrew build symbol-stubs``).
    """
    data_base, raw_end, _section_end = layout_geometry(root / "rebrew-project.toml", target=target)
    orig = data_raw_from_binary(bin_path)
    byte_order = data_byte_order(bin_path)
    toml = data_symbols(metadata, module=_target_module(root, _converge_target(root, target)))
    stub_resolved = stub_file.resolve()
    files = [f for f in scan_files(src_dir, shared_dir) if f.resolve() != stub_resolved]
    references = reference_counts(files)
    by_addr = sorted(toml.items(), key=lambda kv: kv[1])
    toml_next: dict[str, int] = {
        by_addr[i][0]: (by_addr[i + 1][1] if i + 1 < len(by_addr) else raw_end)
        for i in range(len(by_addr))
    }

    stubs = _parse_stub_globals(stub_file)
    owned = 0
    skipped: list[str] = []
    for name, (ctype, decl_n, array_suffix) in sorted(stubs.items()):
        if name not in toml:
            skipped.append(name)
            continue
        addr = toml[name]
        if addr >= raw_end:
            continue  # BSS region — zero-init, nothing to materialize
        base = _ARRAY_SUFFIX_RE.sub("", ctype).strip()
        base_ctype = base
        elemsize = c_type_size(base)
        cap = min(toml_next.get(name, raw_end), raw_end) - addr
        if cap <= 0 or addr < data_base:
            # Below the section base there are no bytes in ``orig``: slicing
            # with a negative start would copy the section's tail into the
            # symbol, and the scalar path would unpack_from a short buffer.
            continue
        off = addr - data_base
        dim = 0
        if decl_n is None:
            # scalar placeholder (TYPE name = 0;); pointers read their full
            # 4-byte value, not the pointee's size.  A slot narrower than the
            # declared type would read the next symbol's bytes, so skip it.
            if cap < elemsize:
                skipped.append(name)
                continue
            size = elemsize
            value = _scalar_literal(orig[off : off + size], base, size, byte_order)
            if value is None:
                skipped.append(name)
                continue
            is_array = False
        else:
            # array placeholder — NUL-terminate char arrays, honor declared
            # element counts, else fill the gap to the next symbol.
            if array_suffix:
                # The fixed shape needs a complete initializer, including any
                # zeros in an inner array.
                size = decl_n * elemsize
                if size > cap or off + size > len(orig):
                    skipped.append(name)
                    continue
            else:
                data_end = orig.find(b"\x00", off, off + cap)
                size = min(
                    cap,
                    data_end - off + 1 if elemsize == 1 and data_end >= 0 else decl_n * elemsize,
                )
            data = orig[off : off + size]
            if not data:
                skipped.append(name)
                continue
            try:
                value, dim = typed_array_literal(base, data, byte_order)
            except ValueError:
                skipped.append(name)  # non-finite float bytes — no C89 literal exists
                continue
            is_array = True
        owner = owner_of([name], files, references)
        if owner is None:
            skipped.append(name)
            continue
        owner_text, _owner_encoding = read_source_text(owner)
        declared = _declared_base_types(owner_text, name)
        if any(_ARRAY_SUFFIX_RE.sub("", base).strip() != base_ctype for base in declared):
            # The owner already names a different type; a placeholder definition
            # in this TU would redeclare the symbol with conflicting types.
            skipped.append(name)
            continue
        if insert_definition(
            owner, name, ctype, dim, value, dry_run, is_array=is_array, array_suffix=array_suffix
        ):
            owned += 1
    return {"owned": owned, "skipped": skipped}


# ---------------------------------------------------------------------------
# data layout fix-ownership: repartition global definitions across TUs
# ---------------------------------------------------------------------------


def _obj_to_source(obj: Path, root: Path, src_dir: Path) -> Path | None:
    """The source file behind a link-order object, or None."""
    # Normalize separators first: wine-produced rsp paths embed ``\\``, and
    # ``str(Path)`` on POSIX keeps them as one component so the CMakeFiles
    # strip never matches.
    s = config_path(obj).as_posix()
    s = _CMAKE_DIR_RE.sub("", s)
    if s.endswith(".obj"):
        s = s[:-4]
    rel = config_path(s)
    for cand in (root / rel, src_dir / rel, src_dir / rel.name):
        if cand.exists():
            return cand
    return None


def _defined_globals_in_text(text: str) -> list[str]:
    """Names of initialized file-scope variable definitions in *text*."""
    found: list[str] = []
    for decl_node, raw in _iter_file_scope_decls(text):
        for child in decl_node.children_by_field_name("declarator"):
            if child.type != "init_declarator":
                continue
            analyzed = _analyze_var_declarator(child, raw)
            if analyzed is not None:
                found.append(analyzed[0])
    return found


def _find_definition(text: str, name: str) -> tuple[int, int, str, str] | None:
    """(start, end, type, size_suffix) of *name*'s initialized definition in *text*, or None."""
    if name not in text:
        return None
    for decl_node, raw in _iter_file_scope_decls(text):
        declarators = decl_node.children_by_field_name("declarator")
        if len(declarators) != 1:
            continue
        child = declarators[0]
        if child.type != "init_declarator":
            continue
        analyzed = _analyze_var_declarator(child, raw)
        if analyzed is None or analyzed[0] != name:
            continue
        _var_name, _is_ptr_to_arr, own_brackets, _ptr_prefix = analyzed
        decl_inner = child.child_by_field_name("declarator")
        type_end = int(decl_inner.start_byte) if decl_inner is not None else int(child.start_byte)
        typ = _WS_RE.sub(
            " ",
            raw[int(decl_node.start_byte) : type_end].decode("utf-8", errors="surrogateescape"),
        ).strip()
        start = _line_indent_start(text, _byte_to_char(text, raw, int(decl_node.start_byte)))
        end = _byte_to_char(text, raw, int(decl_node.end_byte))
        return start, end, typ, own_brackets
    return None


def _definition_to_extern(span: str) -> str:
    """The ``extern`` left behind when a definition moves to another file.

    Uses ``tree-sitter-c`` to slice the declarator before the initializer
    (``init_declarator``), keeping complex declarators such as
    ``int (*table[2])[3] = {0};`` intact.
    """
    from rebrew.c_parser import mask_msvc_syntax, parse_c_source

    body = span.strip()
    if not body:
        return "extern ;"
    probe = body if body.endswith(";") else body + ";"
    masked = mask_msvc_syntax(probe)
    tree, _masked_bytes = parse_c_source(masked)
    raw = probe.encode("utf-8", errors="surrogateescape")
    decl_node = next((c for c in tree.root_node.named_children if c.type == "declaration"), None)
    if decl_node is not None and not decl_node.has_error:
        declarators = decl_node.children_by_field_name("declarator")
        if len(declarators) == 1 and declarators[0].type == "init_declarator":
            inner = declarators[0].child_by_field_name("declarator")
            if inner is not None:
                head = (
                    raw[int(decl_node.start_byte) : int(inner.end_byte)]
                    .decode("utf-8", errors="surrogateescape")
                    .rstrip()
                )
                if not _decl_has_extern(decl_node, raw):
                    head = f"extern {head}"
                return f"{head};"
    head = body[:-1].rstrip() if body.endswith(";") else body
    if _EXTERN_AT_START_RE.match(head) is None:
        head = f"extern {head}"
    return f"{head};"


def _declared_element_count(suffix: str) -> int | None:
    """Element count of a declaration's brackets, or None when it is not constant.

    ``[0x10]`` is 16 and ``[2][4]`` is 8. ``[0]`` stays 0. A name stays unknown.
    """
    if not suffix:
        return None
    from rebrew.c_parser import array_type_shape

    _base, dimensions = array_type_shape(f"char _{suffix}")
    if not dimensions:
        return None
    total = 1
    for bound in dimensions:
        count = _bound_value(bound)
        if count is None:
            return None
        total *= count
    return total


def _decl_info(text: str, name: str) -> tuple[str, int | None] | None:
    """(type, array size or None) of *name*'s existing declaration, or None."""
    if name not in text:
        return None
    for decl_node, raw in _iter_file_scope_decls(text):
        for child in decl_node.children_by_field_name("declarator"):
            analyzed = _analyze_var_declarator(child, raw)
            if analyzed is None or analyzed[0] != name:
                continue
            _var_name, is_ptr_to_arr, own_brackets, ptr_prefix = analyzed
            decl_inner = (
                child.child_by_field_name("declarator")
                if child.type == "init_declarator"
                else child
            )
            type_end = (
                int(decl_inner.start_byte) if decl_inner is not None else int(child.start_byte)
            )
            base = _WS_RE.sub(
                " ",
                raw[int(decl_node.start_byte) : type_end].decode("utf-8", errors="surrogateescape"),
            ).strip()
            if is_ptr_to_arr:
                return base, None
            typ = f"{base} {ptr_prefix}".strip() if ptr_prefix else base
            return typ, _declared_element_count(own_brackets)
    return None


def _merged_definition_line(dtyp: str, dsize: int | None, name: str, def_line: str) -> str:
    """The definition line to append when *name* is already declared in the TU.

    *dtyp*/*dsize* come from :func:`_decl_info` (the existing declaration);
    *def_line* is the intended definition (e.g. ``char g_buf[4] = {…};``).  A
    DEFINITION must not keep a declaration's ``extern``, and a brace
    initializer needs the array form: an unsized ``extern char g_buf[];`` used
    to produce ``extern char g_buf = { … };`` — uncompilable C.
    """
    dtyp = _EXTERN_WORD_RE.sub("", dtyp).strip() or dtyp
    init_m = _INIT_RE.search(def_line)
    init = init_m.group(1) if init_m else "0"
    if not init.startswith("{"):
        return f"{dtyp} {name} = {init};"
    if dsize is not None:
        size = str(dsize)
    else:
        size_m = _ARRAY_SIZE_RE.search(def_line)
        size = size_m.group(1) if size_m else str(init.count(",") + 1)
    return f"{dtyp} {name}[{size}] = {init};"


def _data_symbol_types(metadata: Path, module: str | None) -> dict[str, tuple[int, str]]:
    """``{name: (full VA, type)}`` for the .data symbols in the metadata."""
    db = load_data_document(metadata)
    return {
        str(val["name"]): (va, str(val.get("type", "int")))
        for row_module, va, val in iter_data_symbols(db)
        if val.get("name")
        and (module is None or preset_module_key(row_module) == preset_module_key(module))
    }


def fix_ownership(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    dry_run: bool = False,
    target: str | None = None,
    shared_dir: Path | None = None,
) -> dict[str, Any]:
    """Re-assign global ownership so each TU owns one contiguous address run.

    Fixes the layout-audit SPAN/ORDER violations by moving symbol definitions
    between TUs: .data-contributing TUs (in link order) are partitioned at the
    largest address gaps of the metadata symbols, each symbol moves to its
    partition's TU (the old TU keeps an ``extern``), and unowned symbols are
    emitted with their original bytes.
    """
    build_target = _converge_target(root, target)
    toml = _data_symbol_types(metadata, _target_module(root, build_target))
    data_base, raw_end, _section_end = layout_geometry(
        root / "rebrew-project.toml", target=build_target
    )
    orig = data_raw_from_binary(bin_path)
    byte_order = data_byte_order(bin_path)
    files = scan_files(src_dir, shared_dir)

    owner: dict[str, Path] = {}
    # The scan decides every later edit, so an unreadable TU fails here and
    # writes nothing.
    source_text = dict(_read_sources_or_fail(files))
    for f, text in source_text.items():
        for defined in _defined_globals_in_text(text):
            if defined in toml and defined not in owner:
                owner[defined] = f
    original_owner = dict(owner)

    tu_files = [_obj_to_source(obj, root, src_dir) for obj in link_objects(root, build_target)]
    # One pass over the symbol table instead of rescanning it per object: a
    # mature target has thousands of symbols and hundreds of link-order objects.
    owners_of: dict[Path, int] = {}
    for f in owner.values():
        owners_of[f] = owners_of.get(f, 0) + 1
    data_tus = list(dict.fromkeys(tf for tf in tu_files if tf and owners_of.get(tf)))

    all_syms = sorted(toml.keys(), key=lambda n: toml[n][0])
    next_va: dict[str, int] = {
        name: toml[all_syms[i + 1]][0] for i, name in enumerate(all_syms[:-1])
    }
    new_owner: dict[str, Path] = {}
    if len(data_tus) > 1:
        gaps = []
        for i in range(1, len(all_syms)):
            gaps.append((toml[all_syms[i]][0] - toml[all_syms[i - 1]][0], i))
        cuts = sorted(i for _, i in sorted(gaps, reverse=True)[: len(data_tus) - 1])
        seg = 0
        for i, n in enumerate(all_syms):
            if seg < len(cuts) and i >= cuts[seg]:
                seg += 1
            if seg < len(data_tus):
                new_owner[n] = data_tus[seg]

    removals: dict[Path, list[str]] = defaultdict(list)
    additions: dict[Path, list[tuple[str, str, bool]]] = defaultdict(list)
    for name, (addr, typ) in sorted(toml.items(), key=lambda kv: kv[1][0]):
        cur = original_owner.get(name)
        tu = new_owner.get(name) or cur
        if tu is None:
            continue
        if cur is not None:
            text = source_text[cur]
            definition = _find_definition(text, name)
            if definition is None:
                continue
            start, end, source_type, _suffix = definition
            if cur != tu and (
                "static" in source_type.split() or _find_definition(source_text[tu], name)
            ):
                continue
            def_line = text[start:end].strip()
        elif addr < raw_end:
            if addr < data_base:
                # Below the section base ``orig`` has no bytes at this
                # address; a negative offset would read the section tail.
                continue
            elemsize = c_type_size(typ)
            off = addr - data_base
            cap = min(next_va.get(name, raw_end), raw_end) - addr
            if cap < elemsize:
                continue  # slot narrower than the declared type
            end = orig.find(b"\x00", off, off + cap)
            size = end - off + 1 if elemsize == 1 and end >= 0 else elemsize
            data = orig[off : off + size]
            try:
                init, count = typed_array_literal(typ, data, byte_order)
            except ValueError:
                # Non-finite float bytes have no C89 literal — leave the
                # definition in its current TU rather than emit invalid C.
                continue
            def_line = f"{typ} {name}[{count}] = {init};"
        else:
            def_line = f"{typ} {name} = 0;"
        if cur is not None and cur != tu:
            removals[cur].append(name)
        additions[tu].append((name, def_line, cur is not None))

    n_edit = 0
    # The two passes are one transaction: pass one turns every moved
    # definition into an extern and pass two writes the new definitions.  A
    # failure between or inside the passes (ENOSPC, a read-only file, Ctrl+C)
    # would otherwise leave the project declaring globals it defines nowhere,
    # so the pre-write bytes of every touched unit are restored on any exit
    # that is not the normal one.
    original: dict[Path, tuple[str, str]] = {}
    if not dry_run:
        for tu in (*removals, *additions):
            if tu not in original:
                original[tu] = read_source_text(tu)
    try:
        for tu, names in removals.items():
            text, encoding = read_source_text(tu)
            # Collect spans and splice once, back to front: rewriting per name
            # copied the whole translation unit on every iteration, so a header
            # with N moved globals cost O(N * len(text)).  Later lookups see the
            # same text either way, since an extern line only names the global it
            # replaces, which no other name's pattern matches.
            spans: list[tuple[int, int, str]] = []
            for name in names:
                r = _find_definition(text, name)
                if r:
                    s, e, _, _ = r
                    spans.append((s, e, _definition_to_extern(text[s:e])))
                    n_edit += 1
            for s, e, repl in sorted(spans, reverse=True):
                text = text[:s] + repl + text[e:]
            if not dry_run:
                atomic_write_text(tu, text, encoding=encoding)
        for tu, lines in additions.items():
            text, encoding = read_source_text(tu)
            text = text.rstrip("\n") + "\n"
            appended: list[str] = []
            for name, line, moved_definition in lines:
                if _find_definition(text, name):
                    continue
                di = _decl_info(text, name)
                if di and not di[0].startswith("extern"):
                    continue
                if di and not moved_definition:
                    line = _merged_definition_line(di[0], di[1], name, line)
                appended.append(line)
                n_edit += 1
            # Appended definitions are complete one-liners holding a name no
            # other addition references, so scanning the un-appended prefix
            # answers every later lookup the same way.  Joining once also drops
            # the per-line copy of the whole unit.
            if appended:
                text = text + "\n".join(appended) + "\n"
            if not dry_run:
                atomic_write_text(tu, text, encoding=encoding)
    except BaseException:
        # The original failure is still propagating, so every restore gets its
        # own guard: a restore that raises must not skip the TUs after it
        # (each ``atomic_write_text`` is its own commit, so a skipped one stays
        # half-migrated) and must not replace the failure being cleaned up
        # after.  ``BaseException`` rather than ``OSError``, because the
        # exception that got us here is exactly the one most likely to land
        # inside this loop again.
        unrestored: list[Path] = []
        for tu, (text, encoding) in original.items():
            try:
                atomic_write_text(tu, text, encoding=encoding)
            except BaseException:
                # The original failure may itself be the unwritable-directory
                # or out-of-space condition, so the restore is exactly what
                # cannot succeed.  Say which TUs are left half-migrated
                # (extern with the definition written nowhere) instead of
                # leaving it to be found at the next link.
                unrestored.append(tu)
        if unrestored:
            _logger.exception(
                "ownership rollback left %d of %d rewritten TUs modified: %s",
                len(unrestored),
                len(original),
                ", ".join(str(p) for p in unrestored[:_UNREADABLE_REPORT_LIMIT]),
            )
        raise
    return {"edits": n_edit, "moved": sum(len(v) for v in removals.values())}


# ---------------------------------------------------------------------------
# data layout converge: fixed-point .data placement via leading _dlead_ pads
# ---------------------------------------------------------------------------


def _find_dlead_pad(text: str) -> tuple[int, int, str, int, str] | None:
    """Find an existing ``_dlead_`` pad definition/declaration in *text*.

    Returns ``(start, end, pad_name, size, indent)`` where ``[start:end]`` spans
    the entire declaration up to and including the terminating semicolon (and
    any immediate trailing newline).  Returns ``None`` when absent.
    """
    if "_dlead_" not in text:
        return None
    for decl_node, raw in _iter_file_scope_decls(text):
        declarators = decl_node.children_by_field_name("declarator")
        if len(declarators) != 1:
            continue
        analyzed = _analyze_var_declarator(declarators[0], raw)
        if analyzed is None:
            continue
        pad_name, is_ptr_to_arr, own_brackets, _ptr_prefix = analyzed
        if not pad_name.startswith("_dlead_") or is_ptr_to_arr or not own_brackets:
            continue
        count = _declared_element_count(own_brackets)
        if count is None:
            continue
        decl_char_start = _byte_to_char(text, raw, int(decl_node.start_byte))
        start = _line_indent_start(text, decl_char_start)
        indent = text[start:decl_char_start]
        end = _byte_to_char(text, raw, int(decl_node.end_byte))
        if end < len(text) and text[end] == "\n":
            end += 1
        return start, end, pad_name, count, indent
    return None


def _converge_target(root: Path, target: str | None) -> str:
    """The build output name for :func:`converge_layout` (``build/<target>``).

    *target* wins when given; else the project's ``default_target``; else
    the first ``[targets.*]`` entry (same fallback ``load_config`` applies
    when ``--target`` is omitted).
    """
    if target:
        return target
    cfg = load_tomllib(root / "rebrew-project.toml")
    project = cfg.get("project", {})
    default = project.get("default_target")
    if isinstance(default, str) and default:
        return default
    targets: object = cfg.get("targets", {})
    if isinstance(targets, dict) and targets:
        first: object = next(iter(targets))
        if isinstance(first, str):
            return first
    raise ValueError("no targets in rebrew-project.toml (cannot resolve converge build output)")


def built_data_va(dll: Path) -> int:
    """image-base-correct .data VA of a built DLL (never hardcode)."""
    info = load_binary(dll)
    sec = info.sections.get(".data")
    if sec is None:
        raise ValueError("no .data section in the built DLL")
    return sec.va


def built_text_va(dll: Path) -> int:
    """image-base-correct .text VA of a built binary (never hardcode)."""
    info = load_binary(dll)
    sec = info.sections.get(".text")
    if sec is None:
        raise ValueError("no .text section in the built binary")
    return sec.va


def _target_module(root: Path, target: str) -> str | None:
    """The metadata module key for *target*, or None when the config has none.

    A multi-target store keeps one address per binary for the same name;
    converge must compare its build against its own module only, or a client
    run reads the server's VAs and proposes a pad of gigabytes.
    """
    config = root / "rebrew-project.toml"
    if not config.is_file():
        return None
    cfg = load_tomllib(config)
    targets = cfg.get("targets") or {}
    entry = targets.get(target) or {}
    module = entry.get("module")
    return module if isinstance(module, str) and module else None


def converge_layout(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    rounds: int = 1,
    dry_run: bool = False,
    target: str | None = None,
) -> dict[str, Any]:
    """Fixed-point convergence of .data placement via ``_dlead_<tu>[N]`` pads.

    per-OBJ walk of the build (in link order) gives each TU's actual .data
    start.  For every TU owning metadata symbols, delta = expected VA of its
    first symbol - current VA; a leading ``unsigned char _dlead_<n>[N] = {...}``
    pad (original bytes from the reference) is inserted/adjusted so the TU's
    contribution shifts by delta.  Iterate: measure -> adjust.

    rebrew does not invoke the build: ``rounds`` re-measures the SAME
    ``build/<target>``, so a new fixed point requires the caller to rebuild and
    re-run (the flag help and docs/CLI.md say so).  The pads themselves are
    derived from ``link_objects`` + the reference, so one round of measure+adjust
    is what moves the layout.

    The built binary is resolved as ``build/<target>``: pass *target*
    explicitly, else the project's ``default_target``.  Callers that already
    hold a config should pass ``config.target_name``; the backstop read of
    ``rebrew-project.toml`` is only for direct (test/helper) callers.

    Returns per-round pad adjustments.
    """
    # Same target the build output is read from, so the pads are sized against
    # THIS target's .data geometry.
    data_base, _raw_end, _section_end = layout_geometry(
        root / "rebrew-project.toml", target=_converge_target(root, target)
    )
    orig = data_raw_from_binary(bin_path)
    dll = root / "build" / _converge_target(root, target)
    toml = data_symbols(metadata, module=_target_module(root, dll.name))
    if not dll.exists():
        raise FileNotFoundError(f"build output not found: {dll} — build the project first")

    changes: list[dict[str, Any]] = []
    for _rnd in range(rounds):
        data_va = built_data_va(dll)
        tot = 0
        rows: list[tuple[Path, int, dict[str, int]]] = []
        for obj in link_objects(root, dll.name):
            dsize, syms = obj_data_symbol_offsets(obj)
            rows.append((obj, data_va + tot, {s: off for s, off in syms.items() if s in toml}))
            tot += dsize
        for obj, start, syms in rows:
            if not syms:
                continue
            first = min(syms, key=lambda s: toml[s])
            exp = toml[first]
            cur = start + syms[first]
            # relative mode: section-offset convergence (absolute placement is
            # gated by .text size -> section VA shift; offsets are not)
            delta = (exp - data_base) - (cur - data_va)
            if abs(delta) < 4:
                continue
            f = _obj_to_source(obj, root, src_dir)
            if f is None:
                continue
            text, encoding = read_source_text(f)
            pad_info = _find_dlead_pad(text)
            old_size = pad_info[3] if pad_info else 0
            new_size = max(0, old_size + delta)
            if pad_info is None and new_size == 0:
                # No lead pad to shrink: the TU starts too late for a pad to
                # fix.  Inserting an empty line here grew the TU on every run.
                continue
            pad_name = pad_info[2] if pad_info else "_dlead_" + _NON_WORD_RE.sub("_", f.stem)
            indent = pad_info[4] if pad_info else ""
            if new_size > 0 and exp - new_size >= data_base:
                off = (exp - new_size) - data_base
                data = orig[off : off + new_size]
                decl_line = f"{indent}unsigned char {pad_name}[{new_size}] = {hex_list(data)};\n"
            elif new_size > 0:
                decl_line = f"{indent}unsigned char {pad_name}[{new_size}];\n"
            else:
                # The pad shrank to nothing — emit NO declaration.  `[0]` is
                # not valid C89 and would break the very build this tool
                # converges.
                decl_line = ""
            if pad_info:
                start, end, _, _, _ = pad_info
                text = text[:start] + decl_line + text[end:]
            else:
                new_text = _PAD_INSERT_RE.sub(r"\1" + decl_line, text, count=1)
                if decl_line not in new_text:
                    new_text = decl_line + text
                text = new_text
            if not dry_run:
                atomic_write_text(f, text, encoding=encoding)
            changes.append(
                {
                    "tu": f.relative_to(root).as_posix(),
                    "first": first,
                    "expected": f"0x{exp:x}",
                    "current": f"0x{cur:x}",
                    "delta": delta,
                    "pad": f"0x{new_size:x}",
                }
            )
    return {"rounds": rounds, "adjustments": changes}
