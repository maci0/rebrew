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

import re
import struct
import subprocess
import tomllib
from collections import defaultdict
from pathlib import Path
from typing import Any

from rebrew.cli import error_exit

# ---------------------------------------------------------------------------
# Link order + per-TU symbol inventory (objdump-based)
# ---------------------------------------------------------------------------

_OBJ_RE = re.compile(r'"([^"]+\.obj)"|(?:^|\s)(\S+\.obj)(?=\s|$)')


def link_objects(root: Path) -> list[Path]:
    """The build's object files in link order (build/CMakeFiles/*/objects*.rsp)."""
    rsps = sorted((root / "build/CMakeFiles").glob("*/objects*.rsp"))
    if not rsps:
        error_exit("no build/CMakeFiles/*/objects*.rsp found — build the project first")
    text = rsps[0].read_text()
    return [Path(root / "build") / (a or b) for a, b in _OBJ_RE.findall(text)]


def obj_data_symbols(obj: Path) -> tuple[int, int, set[str], set[str]]:
    """``(dsize, bsize, .data symbols, .bss symbols)`` of one object file."""
    h = subprocess.run(["objdump", "-h", str(obj)], capture_output=True, text=True).stdout
    secs = re.findall(r"^\s+(\d+)\s+(\S+)\s+([0-9a-f]+)\s", h, re.M)
    secname = {int(a): b for a, b, _ in secs}
    dsize = sum(int(c, 16) for a, b, c in secs if b == ".data")
    bsize = sum(int(c, 16) for a, b, c in secs if b == ".bss")
    t = subprocess.run(["objdump", "-t", str(obj)], capture_output=True, text=True).stdout
    dsyms: set[str] = set()
    bsyms: set[str] = set()
    for line in t.splitlines():
        m = re.match(r"\[ *\d+\]\(sec +(-?\d+)\)", line)
        if not m:
            continue
        vm = re.search(r"\s(?:0x)?([0-9a-f]{8})\s+(\S+)\s*$", line[m.end() :])
        if not vm:
            continue
        sym = vm.group(2).lstrip("_")
        if not sym or sym.startswith(".") or sym.startswith("@"):
            continue
        sname = secname.get(int(m.group(1)) - 1)
        if sname == ".data":
            dsyms.add(sym)
        elif sname == ".bss":
            bsyms.add(sym)
    return dsize, bsize, dsyms, bsyms


def obj_data_symbol_offsets(obj: Path) -> tuple[int, dict[str, int]]:
    """(obj .data size, {symbol: offset within the obj's .data})."""
    h = subprocess.run(["objdump", "-h", str(obj)], capture_output=True, text=True).stdout
    secs = re.findall(r"^\s+(\d+)\s+(\S+)\s+([0-9a-f]+)\s", h, re.M)
    secname = {int(a): b for a, b, _ in secs}
    dsize = sum(int(c, 16) for a, b, c in secs if b == ".data")
    t = subprocess.run(["objdump", "-t", str(obj)], capture_output=True, text=True).stdout
    syms: dict[str, int] = {}
    for line in t.splitlines():
        m = re.match(r"\[ *\d+\]\(sec +(-?\d+)\)", line)
        if not m:
            continue
        vm = re.search(r"\s(?:0x)?([0-9a-f]{8})\s+(\S+)\s*$", line[m.end() :])
        if not vm:
            continue
        if secname.get(int(m.group(1)) - 1) == ".data":
            syms[vm.group(2).lstrip("_")] = int(vm.group(1), 16)
    return dsize, syms


# ---------------------------------------------------------------------------
# Data metadata + layout geometry
# ---------------------------------------------------------------------------


def data_symbols(metadata: Path) -> dict[str, int]:
    """``{name: full VA}`` for every ``.data`` symbol in the metadata."""
    with open(metadata, "rb") as fh:
        db = tomllib.load(fh)
    out: dict[str, int] = {}
    for key, val in db.items():
        if val.get("section") != ".data" or not val.get("name"):
            continue
        try:
            out[str(val["name"])] = int(key.rsplit(".", 1)[1], 16)
        except (IndexError, ValueError):
            continue
    return out


def layout_geometry(project_toml: Path) -> tuple[int, int, int]:
    """``(data_base, raw_end, section_end)`` full-VA from the layout metadata.

    ``data_base`` = image_base + .data va; ``raw_end`` = base + raw size;
    ``section_end`` = base + VirtualSize (the BSS tail end).
    """
    with open(project_toml, "rb") as fh:
        cfg = tomllib.load(fh)
    for _target, tcfg in cfg.get("targets", {}).items():
        for s in tcfg.get("layout", {}).get("sections", []):
            if s.get("name") == ".data":
                image_base = int(tcfg.get("layout", {}).get("image_base", 0) or 0)
                va = int(s["va"])
                raw = int(s["raw"])
                vs = int(s["vs"])
                return image_base + va, image_base + va + raw, image_base + va + vs
    raise ValueError("no .data section in the layout metadata (run rebrew gen-layout first)")


def _data_raw_from_binary(bin_path: Path) -> bytes:
    """The reference's raw .data bytes."""
    d = bin_path.read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    sh = e + 24 + optsz
    for i in range(n):
        h = sh + i * 40
        if d[h : h + 8].rstrip(b"\0") == b".data":
            vals: tuple[int, int, int, int] = struct.unpack_from("<IIII", d, h + 8)
            return d[vals[3] : vals[3] + vals[2]]
    raise ValueError("no .data section in the reference binary")


# ---------------------------------------------------------------------------
# Ownership + source edits
# ---------------------------------------------------------------------------


def ref_counts(name: str, files: list[Path]) -> dict[Path, int]:
    counts: dict[Path, int] = defaultdict(int)
    for f in files:
        try:
            t = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        counts[f] += len(re.findall(rf"\b{re.escape(name)}\b", t))
    return counts


def owner_of(names: list[str], files: list[Path]) -> Path | None:
    """The most-referencing file over *names* (None when nothing references them)."""
    counts: dict[Path, int] = defaultdict(int)
    for n in names:
        for f, c in ref_counts(n, files).items():
            counts[f] += c
    if not counts:
        return None
    return max(counts, key=lambda p: counts[p])


def hex_list(data: bytes) -> str:
    out = []
    for i in range(0, len(data), 16):
        out.append("    " + ", ".join(f"0x{b:02x}" for b in data[i : i + 16]) + ",")
    return "{\n" + "\n".join(out) + "\n}"


def insert_definition(
    f: Path, name: str, ctype: str, size: int, init_text: str | None, dry_run: bool
) -> bool:
    """Define ``ctype name[size] = init_text;`` in *f*, replacing an extern decl."""
    lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
    extern_re = re.compile(
        r"^(\s*)extern\s+([A-Za-z_][\w\s]*\**)\s+"
        + re.escape(name)
        + r"\s*(?:\[\s*\d*\s*\])\s*;\s*$"
    )
    def_line = f"{ctype} {name}[{size}]"
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


def audit_layout(root: Path, metadata: Path) -> dict[str, Any]:
    """Per-TU .data/.bss span/order feasibility report.

    Returns rows (per TU: symbol count, min/max addr, data/bss sizes, flags),
    the violation count, and the unowned/duplicate-owned symbol lists.
    """
    toml = data_symbols(metadata)
    owner: dict[str, list[str]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    for obj in link_objects(root):
        dsize, bsize, dsyms, bsyms = obj_data_symbols(obj)
        name = str(obj).split(".dir/")[-1]
        rows.append(
            {
                "obj": name,
                "dsize": dsize,
                "bsize": bsize,
                "dsyms": sorted(dsyms),
                "bsyms": sorted(bsyms),
            }
        )
        for sym in dsyms | bsyms:
            if sym in toml:
                owner[sym].append(name)

    violations = 0
    prev_max: int | None = None
    for r in rows:
        all_syms = set(r["dsyms"]) | set(r["bsyms"])
        syms = sorted(toml[s] for s in all_syms if s in toml)
        lo = syms[0] if syms else 0
        hi = syms[-1] if syms else 0
        flags: list[str] = []
        if syms and prev_max is not None and lo < prev_max:
            flags.append("ORDER")
            violations += 1
        if syms and hi - lo > 0x4000:
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
) -> dict[str, int]:
    """Emit ``_dpad_<addr>[N]`` pads for the uncovered .data byte runs.

    Initialized-region gaps (below the raw end) are filled byte-exact from
    the reference binary; BSS gaps (beyond the raw end, to the section VS)
    become zero-init pads.  The owner TU of each pad is the most-referencing
    file of the following symbol (leading run: the first symbol's owner).
    Returns ``{"init_pads": n, "bss_pads": n}``.
    """
    data_base, raw_end, section_end = layout_geometry(root / "rebrew-project.toml")
    orig = _data_raw_from_binary(bin_path)
    toml = data_symbols(metadata)
    files = sorted(src_dir.rglob("*.c"))
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
