"""data_layout.py — shared .data/.bss placement model for byte-identity builds.

The linked ``.data`` section is the concatenation of per-TU contributions in
link order.  For the layout to converge to the original (byte-identity), the
raw region must be filled byte-exact and the BSS tail must reach the
reference's VirtualSize.  This module provides the shared machinery used by
``rebrew data --layout-audit`` and ``rebrew data --fill-data`` (and
``rebrew verify-placement``):

- ``link_objects`` — the link's object files in link order (objects*.rsp);
- ``obj_data_symbols`` — a TU's .data/.bss size + owned symbol offsets;
- ``data_symbols`` — the .data symbol map from ``rebrew-data.toml``;
- ``owner_of`` — the most-referencing TU for a set of symbols;
- ``emit_pad`` / ``insert_definition`` — write ``_dpad_<addr>[N]`` pads into
  an owning TU's source.

All addresses are full image VAs; the section geometry (``data_base``,
``raw_end``, ``section_end``) comes from the layout metadata
(``[targets.<t>.layout]`` sections), so nothing is hardcoded per project.
"""

from __future__ import annotations

import math
import re
import struct
import subprocess
import tomllib
from collections import defaultdict
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from rebrew.binary_loader import load_binary
from rebrew.data_metadata import iter_data_symbols
from rebrew.utils import atomic_write_text, read_source_text

# ---------------------------------------------------------------------------
# Link order + per-TU symbol inventory (objdump-based)
# ---------------------------------------------------------------------------

_OBJ_RE = re.compile(r'"([^"]+\.obj)"|(?:^|\s)(\S+\.obj)(?=\s|$)')

#: Wall-clock cap for one objdump invocation.
_OBJDUMP_TIMEOUT_S = 60


def _run_objdump(obj: Path, flag: str) -> str:
    """Run ``objdump <flag> <obj>`` and return stdout.

    Raises with the command and stderr when objdump is missing, fails, or
    times out — an unchecked run would silently yield zero sizes and an
    empty symbol set, turning every downstream audit row into garbage.
    """
    try:
        r = subprocess.run(
            ["objdump", flag, str(obj)],
            capture_output=True,
            text=True,
            timeout=_OBJDUMP_TIMEOUT_S,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"objdump not found on PATH (needed for {obj})") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"objdump {flag} timed out after {_OBJDUMP_TIMEOUT_S}s: {obj}") from exc
    if r.returncode != 0:
        raise RuntimeError(
            f"objdump {flag} failed on {obj} (rc={r.returncode}): {r.stderr.strip()}"
        )
    return r.stdout


def link_objects(root: Path) -> list[Path]:
    """The build's object files in link order.

    CMake builds are read from ``build/CMakeFiles/*/objects*.rsp``, which
    preserves the link order.  Makefile-style builds (no rsp) fall back to
    the object directory (``out/`` then ``build/``) sorted by name — GNU
    make expands ``$(wildcard ...)``/``$(SRCS)`` in sorted order, so a plain
    Makefile links objects in exactly that order.
    """
    rsps = sorted((root / "build/CMakeFiles").glob("*/objects*.rsp"))
    if rsps:
        text = rsps[0].read_text(encoding="utf-8")
        return [Path(root / "build") / (a or b) for a, b in _OBJ_RE.findall(text)]
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


def _obj_sections(obj: Path) -> tuple[dict[int, str], int, int]:
    """``(section index → name, .data size, .bss size)`` from ``objdump -h``."""
    secname, sizes = _obj_section_sizes(obj)
    return secname, sizes.get(".data", 0), sizes.get(".bss", 0)


def _obj_section_sizes(obj: Path) -> tuple[dict[int, str], dict[str, int]]:
    """``(section index → name, {section name: size})`` from ``objdump -h``."""
    h = _run_objdump(obj, "-h")
    secs = re.findall(r"^\s+(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s", h, re.M)
    secname = {int(a): b for a, b, _ in secs}
    sizes: dict[str, int] = {}
    for _a, b, c in secs:
        sizes[b] = sizes.get(b, 0) + int(c, 16)
    return secname, sizes


def _iter_obj_symbols(obj: Path) -> Iterator[tuple[int, int, str]]:
    """Yield ``(section index, value, raw name)`` for each ``objdump -t`` symbol line."""
    t = _run_objdump(obj, "-t")
    for line in t.splitlines():
        m = re.match(r"\[ *\d+\]\(sec +(-?\d+)\)", line)
        if not m:
            continue
        vm = re.search(r"\s(?:0x)?([0-9a-fA-F]+)\s+(\S+)\s*$", line[m.end() :])
        if not vm:
            continue
        yield int(m.group(1)), int(vm.group(1), 16), vm.group(2)


def obj_data_symbols(obj: Path) -> tuple[int, int, set[str], set[str]]:
    """``(dsize, bsize, .data symbols, .bss symbols)`` of one object file."""
    sizes, buckets = obj_section_symbols(obj, ".data", ".bss")
    return sizes[".data"], sizes[".bss"], buckets[".data"], buckets[".bss"]


def obj_section_symbols(obj: Path, *sections: str) -> tuple[dict[str, int], dict[str, set[str]]]:
    """``({section: size}, {section: symbols})`` of one object file.

    Generalization of :func:`obj_data_symbols` for extra sections (``.rdata``).
    Only the requested sections are inventoried.
    """
    secname, sizes = _obj_section_sizes(obj)
    buckets: dict[str, set[str]] = {s: set() for s in sections}
    for sec_idx, _value, raw_sym in _iter_obj_symbols(obj):
        sym = raw_sym.lstrip("_")
        if not sym or sym.startswith((".", "@")):
            continue
        sname = secname.get(sec_idx - 1)
        if sname in buckets:
            buckets[sname].add(sym)
    return {s: sizes.get(s, 0) for s in sections}, buckets


def obj_data_symbol_offsets(obj: Path) -> tuple[int, dict[str, int]]:
    """(obj .data size, {symbol: offset within the obj's .data})."""
    secname, dsize, _bsize = _obj_sections(obj)
    syms: dict[str, int] = {}
    for sec_idx, value, raw_sym in _iter_obj_symbols(obj):
        if secname.get(sec_idx - 1) == ".data":
            syms[raw_sym.lstrip("_")] = value
    return dsize, syms


def obj_text_symbol_offsets(obj: Path) -> tuple[int, dict[str, int]]:
    """(obj .text size, {symbol: offset within the obj's .text}).

    Same shape as :func:`obj_data_symbol_offsets`, for the ``.text`` side —
    the primitive ``rebrew text-audit`` walks per TU in link order.
    """
    secname, sizes = _obj_section_sizes(obj)
    syms: dict[str, int] = {}
    for sec_idx, value, raw_sym in _iter_obj_symbols(obj):
        if secname.get(sec_idx - 1) == ".text":
            syms[raw_sym.lstrip("_")] = value
    return sizes.get(".text", 0), syms


# ---------------------------------------------------------------------------
# Data metadata + layout geometry
# ---------------------------------------------------------------------------


def data_symbols(metadata: Path, section: str | Sequence[str] | None = ".data") -> dict[str, int]:
    """``{name: full VA}`` for every symbol in *section* of the metadata.

    *section* is one name, a set of names, or ``None`` for every section.  The
    default (``.data``) is the historical contract; callers that model the
    section tail pass ``(".data", ".bss")`` — BSS globals carry
    ``section=".bss"`` (``rebrew data --set-type`` / the Ghidra import), so a
    ``.data``-only read silently drops them.
    """
    with open(metadata, "rb") as fh:
        db = tomllib.load(fh)
    wanted = None if section is None else {section} if isinstance(section, str) else set(section)
    return {
        str(val["name"]): va
        for _, va, val in iter_data_symbols(db, None)
        if val.get("name") and (wanted is None or val.get("section") in wanted)
    }


def layout_geometry(project_toml: Path, target: str | None = None) -> tuple[int, int, int]:
    """``(data_base, raw_end, section_end)`` full-VA from the layout metadata.

    ``data_base`` = image_base + .data va; ``raw_end`` = base + raw size;
    ``section_end`` = base + VirtualSize (the BSS tail end).

    *target* selects the ``[targets.*]`` entry; without it the project's
    ``default_target`` is used, falling back to the first declared target.  The
    old code always read the FIRST target, so a multi-target project sized
    ``data --converge``'s pads against another binary's geometry.
    """
    with open(project_toml, "rb") as fh:
        cfg = tomllib.load(fh)
    targets = cfg.get("targets", {})
    if target:
        tcfg = targets.get(target)
        if tcfg is None:
            raise ValueError(f"no [targets.{target}] in {project_toml}")
        candidates = [(target, tcfg)]
    else:
        default = str(cfg.get("project", {}).get("default_target") or "")
        if default and default in targets:
            candidates = [(default, targets[default])]
        else:
            candidates = list(targets.items())
    for _target, tcfg in candidates:
        for s in tcfg.get("layout", {}).get("sections", []):
            if s.get("name") == ".data":
                image_base = int(tcfg.get("layout", {}).get("image_base", 0) or 0)
                va = int(s["va"])
                raw = int(s["raw"])
                vs = int(s["vs"])
                return image_base + va, image_base + va + raw, image_base + va + vs
    raise ValueError("no .data section in the layout metadata (run rebrew gen-layout first)")


def data_raw_from_binary(bin_path: Path) -> bytes:
    """The reference's raw .data bytes."""
    info = load_binary(bin_path)
    sec = info.sections.get(".data")
    if sec is None:
        raise ValueError("no .data section in the reference binary")
    return info.data[sec.file_offset : sec.file_offset + sec.raw_size]


# ---------------------------------------------------------------------------
# Ownership + source edits
# ---------------------------------------------------------------------------


def owner_of(names: list[str], files: list[Path]) -> Path | None:
    """The most-referencing file over *names* (None when nothing references them)."""
    if not names:
        return None
    patterns = [re.compile(rf"\b{re.escape(n)}\b") for n in names]
    counts: dict[Path, int] = defaultdict(int)
    for f in files:
        try:
            t = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in patterns:
            counts[f] += len(pat.findall(t))
    if not counts:
        return None
    return max(counts, key=lambda p: counts[p])


def hex_list(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 16):
        out.append("    " + ", ".join(f"0x{b:02x}" for b in data[i : i + 16]) + ",")
    return "{\n" + "\n".join(out) + "\n}"


def insert_definition(
    f: Path,
    name: str,
    ctype: str,
    size: int,
    init_text: str | None,
    dry_run: bool,
    is_array: bool = True,
) -> bool:
    """Define ``ctype name = init;`` / ``ctype name[size] = init;`` in *f*.

    Replaces an existing matching ``extern`` line in place (keeping its
    indentation); appends the definition when the TU has no such extern.
    With ``is_array=False`` a scalar ``TYPE name = value;`` is emitted.
    """
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    if is_array:
        extern_re = re.compile(
            r"^(\s*)extern\s+([A-Za-z_][\w\s]*\**)\s+"
            + re.escape(name)
            + r"\s*(?:\[\s*\d*\s*\])\s*;\s*$"
        )
        def_line = f"{ctype} {name}[{size}]"
    else:
        extern_re = re.compile(
            r"^(\s*)extern\s+([A-Za-z_][\w\s]*\**)\s+" + re.escape(name) + r"\s*;\s*$"
        )
        def_line = f"{ctype} {name}"
    if init_text:
        def_line += f" = {init_text}"
    def_line += ";"
    for i, ln in enumerate(lines):
        m = extern_re.match(ln)
        if m:
            lines[i] = m.group(1) + def_line
            if not dry_run:
                f.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return True
    lines.append(def_line)
    if not dry_run:
        f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# layout-audit
# ---------------------------------------------------------------------------


def audit_layout(root: Path, metadata: Path, section: str = ".data") -> dict[str, Any]:
    """Per-TU span/order feasibility report for *section* (``.data`` or ``.rdata``).

    Returns rows (per TU: symbol count, min/max addr, section sizes, flags),
    the violation count, and the unowned/duplicate-owned symbol lists.
    ``.bss`` symbols ride along for ordering context in ``.data`` mode only.
    """
    toml = data_symbols(metadata, section)
    owner: dict[str, list[str]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    violations = 0
    extra = (".bss",) if section == ".data" else ()
    for obj in link_objects(root):
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


def fill_data(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    dry_run: bool = False,
    bss_only: bool = False,
    target: str | None = None,
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
    """
    data_base, raw_end, section_end = layout_geometry(root / "rebrew-project.toml", target=target)
    orig = data_raw_from_binary(bin_path)
    # Both sections: `.bss` globals (section=".bss" in the metadata) live past
    # raw_end and become the zero-init pads — a `.data`-only read dropped them,
    # so BSS pads were never emitted and `--bss-only` was a no-op.
    toml = data_symbols(metadata, (".data", ".bss"))
    files = sorted(p for p in src_dir.rglob("*.c") if not p.is_symlink())
    by_addr = sorted(toml.items(), key=lambda kv: kv[1])
    if not by_addr:
        return {"init_pads": 0, "bss_pads": 0}

    n_bss = n_pad = 0

    # leading pad: raw section start -> first symbol
    first_name, first_addr = by_addr[0]
    lead = first_addr - data_base
    if lead > 0 and first_addr < raw_end and not bss_only:
        owner = owner_of([first_name], files)
        if owner:
            data = orig[:lead]
            init = hex_list(data)
            if insert_definition(
                owner, f"_dpad_{data_base:x}", "unsigned char", lead, init, dry_run
            ):
                n_pad += 1

    for i, (name, addr) in enumerate(by_addr):
        nxt_addr = by_addr[i + 1][1] if i + 1 < len(by_addr) else section_end
        gap = nxt_addr - addr
        if gap <= 0x40:
            continue  # small alignment gaps only
        owner = owner_of([name] + ([by_addr[i + 1][0]] if i + 1 < len(by_addr) else []), files)
        if owner is None:
            continue
        if bss_only and addr < raw_end:
            continue
        if addr >= raw_end:
            # BSS region: anonymous zero-init pad (named symbols keep their
            # scalar/field identity; the array region is the gap itself)
            if insert_definition(owner, f"_dpad_{addr:x}", "unsigned char", gap, None, dry_run):
                n_bss += 1
        else:
            # initialized region: byte-exact run from the original
            start = addr - data_base
            end = min(nxt_addr, raw_end) - data_base
            if end > start:
                data = orig[start:end]
                init = hex_list(data)
                if insert_definition(
                    owner, f"_dpad_{addr:x}", "unsigned char", end - start, init, dry_run
                ):
                    n_pad += 1
    return {"init_pads": n_pad, "bss_pads": n_bss}


# ---------------------------------------------------------------------------
# data --own: materialize stub-file globals as real definitions
# ---------------------------------------------------------------------------

_STUB_DEF_RE = re.compile(
    r"^\s*([\w\s\*]+?)\s+(\w+)(?:\[(0x[0-9a-fA-F]+|\d+)\])?\s*=\s*(?:\{[^;]*\}|[^;]+);\s*$"
)


def _parse_stub_globals(stub_file: Path) -> dict[str, tuple[str, int | None]]:
    """``name -> (type, declared array size or None for scalars)`` from a stubs TU."""
    out: dict[str, tuple[str, int | None]] = {}
    for line in stub_file.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _STUB_DEF_RE.match(line)
        if not m:
            continue
        typ = " ".join(m.group(1).split())
        if typ == "extern":
            continue
        out[m.group(2)] = (typ, int(m.group(3), 0) if m.group(3) else None)
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
    "unsigned short": 2,
    "signed short": 2,
    "wchar_t": 2,
    "WORD": 2,
    "int": 4,
    "unsigned int": 4,
    "signed int": 4,
    "long": 4,
    "unsigned long": 4,
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
}

_ARRAY_SUFFIX_RE = re.compile(r"\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]")

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
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|__int64", text)
    while words and words[0] in _NON_TYPE_WORDS:
        words.pop(0)
    while words and words[-1] not in _TYPE_SIZES and " ".join(words[-2:]) not in _TYPE_PHRASES:
        words.pop()
    if not words:
        return 4
    for width in (3, 2, 1):
        if len(words) >= width and " ".join(words[-width:]) in _TYPE_SIZES:
            return _TYPE_SIZES[" ".join(words[-width:])]
    return 4


def estimate_type_size(type_str: str) -> int:
    """Byte size of a declared C type string (pointer- and array-aware)."""
    arr = _ARRAY_SUFFIX_RE.search(type_str)
    elem_count = int(arr.group(1), 0) if arr else 1
    return c_type_size(type_str) * elem_count


def typed_array_literal(ctype: str, data: bytes) -> tuple[str, int]:
    """C initializer text + element count for *data* read as *ctype* elements.

    Byte-sized elements keep :func:`hex_list`'s raw-byte layout; wider
    elements are formatted per element so ``int arr[3]`` emits three ints
    instead of twelve bytes under an inflated dimension.

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
        lit = _scalar_literal(data[off : off + elemsize], ctype, elemsize)
        if lit is None:
            raise ValueError(
                f"{ctype} element at byte {off} has no C89 literal (non-finite float/double bytes)"
            )
        elems.append(lit)
    lines = ["    " + ", ".join(elems[i : i + 16]) + "," for i in range(0, len(elems), 16)]
    return "{\n" + "\n".join(lines) + "\n}", len(elems)


def _scalar_literal(data: bytes, ctype: str, size: int) -> str | None:
    """A C initializer for *data* as *ctype* (None when the bytes don't fit).

    Floats and doubles (including the ``FLOAT``/``DOUBLE`` Windows typedefs)
    emit decimal literals whose widened-double repr round-trips to the exact
    original bits under any conforming compiler.  Non-finite values return
    None: C89 has no NaN/Inf literal, and an integer fallback would be
    implicitly converted to a completely different value.
    """
    if "*" in ctype:
        if len(data) >= 4:
            v = struct.unpack_from("<I", data)[0]
            return "0" if v == 0 else f"(void*) 0x{v:08x}"
        return None
    base = ctype.rstrip("*").strip().lower()
    if base == "float":
        if len(data) < 4:
            return None
        v = struct.unpack_from("<f", data)[0]
        return f"{v!r}f" if math.isfinite(v) else None
    if base == "double":
        if len(data) < 8:
            return None
        v = struct.unpack_from("<d", data)[0]
        return repr(v) if math.isfinite(v) else None
    if size == 1:
        return str(data[0])
    if size == 2:
        return str(struct.unpack_from("<H", data)[0])
    if size == 4:
        v = struct.unpack_from("<I", data)[0]
        return f"0x{v:08x}" if v >= 0x10000000 else str(v)
    if size == 8:
        v = struct.unpack_from("<Q", data)[0]
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
    (``rebrew gen-stubs``).
    """
    data_base, raw_end, _section_end = layout_geometry(root / "rebrew-project.toml", target=target)
    orig = data_raw_from_binary(bin_path)
    toml = data_symbols(metadata)
    stub_resolved = stub_file.resolve()
    files = [f for f in sorted(src_dir.rglob("*.c")) if f.resolve() != stub_resolved]
    by_addr = sorted(toml.items(), key=lambda kv: kv[1])
    toml_next: dict[str, int] = {
        by_addr[i][0]: (by_addr[i + 1][1] if i + 1 < len(by_addr) else raw_end)
        for i in range(len(by_addr))
    }

    stubs = _parse_stub_globals(stub_file)
    owned = 0
    skipped: list[str] = []
    for name, (ctype, decl_n) in sorted(stubs.items()):
        if name not in toml:
            skipped.append(name)
            continue
        addr = toml[name]
        if addr >= raw_end:
            continue  # BSS region — zero-init, nothing to materialize
        base = _ARRAY_SUFFIX_RE.sub("", ctype).strip()
        elemsize = c_type_size(base)
        cap = min(toml_next.get(name, raw_end), raw_end) - addr
        if cap <= 0:
            continue
        off = addr - data_base
        dim = 0
        if decl_n is None:
            # scalar placeholder (TYPE name = 0;); pointers read their full
            # 4-byte value, not the pointee's size.
            size = elemsize
            value = _scalar_literal(orig[off : off + size], base, size)
            if value is None:
                skipped.append(name)
                continue
            is_array = False
        else:
            # array placeholder — NUL-terminate char arrays, honor declared
            # element counts, else fill the gap to the next symbol.
            data_end = orig.find(b"\x00", off, off + cap)
            if elemsize == 1 and data_end >= 0:
                size = data_end - off + 1
            elif decl_n > 1:
                size = decl_n * elemsize
            else:
                size = cap
            size = min(size, cap)
            data = orig[off : off + size]
            if not data:
                skipped.append(name)
                continue
            try:
                value, dim = typed_array_literal(base, data)
            except ValueError:
                skipped.append(name)  # non-finite float bytes — no C89 literal exists
                continue
            is_array = True
        owner = owner_of([name], files)
        if owner is None:
            skipped.append(name)
            continue
        if insert_definition(owner, name, ctype, dim, value, dry_run, is_array=is_array):
            owned += 1
    return {"owned": owned, "skipped": skipped}


# ---------------------------------------------------------------------------
# data --fix-ownership: repartition global definitions across TUs
# ---------------------------------------------------------------------------


def _obj_to_source(obj: Path, root: Path, src_dir: Path) -> Path | None:
    """The source file behind a link-order object, or None."""
    s = re.sub(r"^.*?CMakeFiles/[^/]+\.dir/", "", str(obj))
    if s.endswith(".obj"):
        s = s[:-4]
    for cand in (root / s, src_dir / s, src_dir / Path(s).name):
        if cand.exists():
            return cand
    return None


def _iter_line_spans(text: str) -> Iterator[tuple[int, str]]:
    """Yield ``(start_offset, line)`` for every ``\\n``-delimited line of *text*.

    Offsets come from real newline positions, so CRLF files get byte-exact
    spans (``split("\\n")`` + ``len(line) + 1`` accounting drifts one byte per
    preceding CRLF line and misplaces every spliced edit after it).
    """
    pos = 0
    while True:
        nl = text.find("\n", pos)
        if nl < 0:
            yield pos, text[pos:]
            return
        yield pos, text[pos:nl]
        pos = nl + 1


def _find_definition(text: str, name: str) -> tuple[int, int, str, str] | None:
    """(start, end, type, size_suffix) of *name*'s definition in *text*, or None."""
    pat = re.compile(r"^[ \t]*([\w\s\*]+)\s+" + re.escape(name) + r"(\[\d+\])?\s*=\s*\{")
    start = None
    typ = ""
    sz = ""
    for pos, ln in _iter_line_spans(text):
        m = pat.match(ln)
        if m:
            start, typ, sz = pos, m.group(1).strip(), m.group(2) or ""
            break
    if start is None:
        pat2 = re.compile(r"^[ \t]*([\w\s\*]+\s*\*?)\s+" + re.escape(name) + r"\s*=\s*[^;]+;\s*$")
        for pos, ln in _iter_line_spans(text):
            m = pat2.match(ln)
            if m and m.group(1).strip():
                start, typ, sz = pos, m.group(1).strip(), ""
                break
    if start is None:
        return None
    depth = 0
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0:
            return start, i + 1, typ, sz
        i += 1
    return start, len(text), typ, sz


def _decl_info(text: str, name: str) -> tuple[str, int | None] | None:
    """(type, array size or None) of *name*'s existing declaration, or None."""
    m = re.search(
        r"^[ \t]*([\w\s\*]+?)\s+" + re.escape(name) + r"(\[\s*\d*\s*\])?\s*(?:=|;)", text, re.M
    )
    if not m:
        return None
    size_m = re.search(r"\[(\d+)\]", m.group(2) or "")
    return m.group(1).strip(), (int(size_m.group(1)) if size_m else None)


def _merged_definition_line(dtyp: str, dsize: int | None, name: str, def_line: str) -> str:
    """The definition line to append when *name* is already declared in the TU.

    *dtyp*/*dsize* come from :func:`_decl_info` (the existing declaration);
    *def_line* is the intended definition (e.g. ``char g_buf[4] = {…};``).  A
    DEFINITION must not keep a declaration's ``extern``, and a brace
    initializer needs the array form: an unsized ``extern char g_buf[];`` used
    to produce ``extern char g_buf = { … };`` — uncompilable C.
    """
    dtyp = re.sub(r"\bextern\b\s*", "", dtyp).strip() or dtyp
    init_m = re.search(r"=\s*(\{[^;]*\}|[^;]+);?$", def_line)
    init = init_m.group(1) if init_m else "0"
    if not init.startswith("{"):
        return f"{dtyp} {name} = {init};"
    if dsize is not None:
        size = str(dsize)
    else:
        size_m = re.search(r"\[(\d+)\]", def_line)
        size = size_m.group(1) if size_m else str(init.count(",") + 1)
    return f"{dtyp} {name}[{size}] = {init};"


def _data_symbol_types(metadata: Path) -> dict[str, tuple[int, str]]:
    """``{name: (full VA, type)}`` for the .data symbols in the metadata."""
    with open(metadata, "rb") as fh:
        db = tomllib.load(fh)
    return {
        str(val["name"]): (va, str(val.get("type", "int")))
        for _, va, val in iter_data_symbols(db)
        if val.get("name")
    }


def fix_ownership(
    root: Path,
    metadata: Path,
    bin_path: Path,
    src_dir: Path,
    dry_run: bool = False,
    target: str | None = None,
) -> dict[str, Any]:
    """Re-assign global ownership so each TU owns one contiguous address run.

    Fixes the layout-audit SPAN/ORDER violations by moving symbol definitions
    between TUs: .data-contributing TUs (in link order) are partitioned at the
    largest address gaps of the metadata symbols, each symbol moves to its
    partition's TU (the old TU keeps an ``extern``), and unowned symbols are
    emitted with their original bytes.
    """
    toml = _data_symbol_types(metadata)
    data_base, raw_end, _section_end = layout_geometry(root / "rebrew-project.toml", target=target)
    orig = data_raw_from_binary(bin_path)
    files = sorted(p for p in src_dir.rglob("*.c") if not p.is_symlink())

    def_re = re.compile(r"^[ \t]*[\w\s\*]+\s+(\w+)(?:\[\d+\])?\s*=")
    owner: dict[str, Path] = {}
    for f in files:
        for ln in f.read_text(encoding="utf-8", errors="replace").splitlines():
            m = def_re.match(ln.strip())
            if m and m.group(1) in toml and m.group(1) not in owner:
                owner[m.group(1)] = f
    original_owner = dict(owner)

    tu_files: list[Path | None] = [_obj_to_source(obj, root, src_dir) for obj in link_objects(root)]
    data_tus = list(
        dict.fromkeys(tf for tf in tu_files if tf and any(owner.get(n) == tf for n in toml))
    )

    all_syms = sorted(toml.keys(), key=lambda n: toml[n][0])
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
    additions: dict[Path, list[str]] = defaultdict(list)
    for name, (addr, typ) in sorted(toml.items(), key=lambda kv: kv[1][0]):
        tu = new_owner.get(name) or owner.get(name)
        if tu is None:
            continue
        if addr < raw_end:
            elemsize = c_type_size(typ)
            off = addr - data_base
            end = orig.find(b"\x00", off, off + 0x200)
            size = end - off + 1 if elemsize == 1 and 0 <= end < raw_end - data_base else elemsize
            data = orig[off : off + size]
            try:
                init, count = typed_array_literal(typ, data)
            except ValueError:
                # Non-finite float bytes have no C89 literal — leave the
                # definition in its current TU rather than emit invalid C.
                continue
            def_line = f"{typ} {name}[{count}] = {init};"
        else:
            def_line = f"{typ} {name} = 0;"
        cur = original_owner.get(name)
        if cur and cur != tu:
            removals[cur].append(name)
        additions[tu].append(def_line)

    n_edit = 0
    for tu, names in removals.items():
        text, encoding = read_source_text(tu)
        for name in names:
            r = _find_definition(text, name)
            if r:
                s, e, typ, sz = r
                text = text[:s] + f"extern {typ} {name}{sz};" + text[e:]
                n_edit += 1
        if not dry_run:
            atomic_write_text(tu, text, encoding=encoding)
    for tu, lines in additions.items():
        text, encoding = read_source_text(tu)
        text = text.rstrip("\n") + "\n"
        for line in lines:
            name_m = re.search(r"\s(\w+)(?:\[|\s*=)", line)
            if not name_m:
                continue
            name = name_m.group(1)
            if _find_definition(text, name):
                continue
            di = _decl_info(text, name)
            if di and not di[0].startswith("extern"):
                continue
            if di:
                line = _merged_definition_line(di[0], di[1], name, line)
            text += line + "\n"
            n_edit += 1
        if not dry_run:
            atomic_write_text(tu, text, encoding=encoding)
    return {"edits": n_edit, "moved": sum(len(v) for v in removals.values())}


# ---------------------------------------------------------------------------
# data --converge: fixed-point .data placement via leading _dlead_ pads
# ---------------------------------------------------------------------------

_DLEAD_RE = re.compile(r"^unsigned char (_dlead_\w+)\[(\d+)\]")


def _converge_target(root: Path, target: str | None) -> str:
    """The build output name for :func:`converge_layout` (``build/<target>``).

    *target* wins when given; else the project's ``default_target``; else
    the first ``[targets.*]`` entry (same fallback ``load_config`` applies
    when ``--target`` is omitted).
    """
    if target:
        return target
    with open(root / "rebrew-project.toml", "rb") as fh:
        cfg = tomllib.load(fh)
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
    # THIS target's .data geometry (the old call always read the first target).
    data_base, raw_end, _section_end = layout_geometry(
        root / "rebrew-project.toml", target=_converge_target(root, target)
    )
    orig = data_raw_from_binary(bin_path)
    toml = data_symbols(metadata)
    dll = root / "build" / _converge_target(root, target)
    if not dll.exists():
        raise FileNotFoundError(f"build output not found: {dll} — build the project first")

    changes: list[dict[str, Any]] = []
    for _rnd in range(rounds):
        data_va = built_data_va(dll)
        tot = 0
        rows: list[tuple[Path, int, dict[str, int]]] = []
        for obj in link_objects(root):
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
            m = _DLEAD_RE.search(text)
            old_size = int(m.group(2)) if m else 0
            new_size = max(0, old_size + delta)
            pad_name = "_dlead_" + re.sub(r"\W", "_", f.stem)
            if new_size > 0 and exp - new_size >= data_base:
                off = (exp - new_size) - data_base
                data = orig[off : off + new_size]
                line = f"unsigned char {pad_name}[{new_size}] = {hex_list(data)};"
            elif new_size > 0:
                line = f"unsigned char {pad_name}[{new_size}];"
            else:
                # The pad shrank to nothing — emit NO declaration.  `[0]` is
                # not valid C89 and would break the very build this tool
                # converges.
                line = ""
            if m:
                text = text[: m.start()] + line + text[m.end() :]
            else:
                text = re.sub(
                    r"(\n)(?=\s*(?:extern|static|__declspec|// FUNCTION|// GLOBAL))",
                    r"\1" + line + "\n",
                    text,
                    count=1,
                )
                if line not in text:
                    text = line + "\n" + text
            if not dry_run:
                atomic_write_text(f, text, encoding=encoding)
            changes.append(
                {
                    "tu": str(f.relative_to(root)),
                    "first": first,
                    "expected": f"0x{exp:x}",
                    "current": f"0x{cur:x}",
                    "delta": delta,
                    "pad": f"0x{new_size:x}",
                }
            )
    return {"rounds": rounds, "adjustments": changes}
