"""verify-placement — post-edit check: compare .data symbol VAs vs the metadata.

The linked ``.data`` section is the concatenation of per-TU contributions in
link order.  After editing sources, this command walks the link's object
files (objdump on each obj, in link order), computes every symbol's current
``.data`` VA, and compares it against the data metadata
(``src/rebrew-data.toml``).  Misplaced symbols mean the object order or a
TU's own layout drifted — the reccmp "0 aligned" symptom.

Usage:
    rebrew verify-placement [--data-metadata src/rebrew-data.toml] [--json]
"""

from __future__ import annotations

import re
import struct
import subprocess
import tomllib
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print

console = Console(stderr=True)

app = typer.Typer(
    help="Compare .data symbol VAs of the current build against the data metadata.",
    rich_markup_mode="rich",
)

_OBJ_RE = re.compile(r'"([^"]+\.obj)"|(?:^|\s)(\S+\.obj)(?=\s|$)')


def _link_objects(root: Path) -> list[Path]:
    rsps = sorted((root / "build/CMakeFiles").glob("*/objects*.rsp"))
    if not rsps:
        error_exit("no build/CMakeFiles/*/objects*.rsp found — build the project first")
    text = rsps[0].read_text()
    objs = [Path(root / "build") / (a or b) for a, b in _OBJ_RE.findall(text)]
    return objs


def _data_section_va(dll: Path) -> int:
    """image-base-correct .data VA of *dll* (never hardcode)."""
    d = dll.read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    opt = e + 24
    base_vals: tuple[int, ...] = struct.unpack_from("<I", d, opt + 28)
    base = base_vals[0]
    sh = opt + optsz
    for i in range(n):
        h = sh + i * 40
        if d[h : h + 8].rstrip(b"\0") == b".data":
            vals: tuple[int, int, int, int] = struct.unpack_from("<IIII", d, h + 8)
            return base + vals[1]
    raise ValueError("no .data section in the built DLL")


def _expected(root: Path, metadata: Path) -> dict[str, int]:
    with open(metadata, "rb") as f:
        doc = tomllib.load(f)
    out: dict[str, int] = {}
    for key, val in doc.items():
        if val.get("section") == ".data" and val.get("name"):
            try:
                out[str(val["name"])] = int(key.rsplit(".", 1)[1], 16)
            except (IndexError, ValueError):
                continue
    return out


def _obj_data_symbols(obj: Path) -> tuple[int, dict[str, int]]:
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
        sec = int(m.group(1))
        vm = re.search(r"\s(?:0x)?([0-9a-f]{8})\s+(\S+)\s*$", line[m.end() :])
        if not vm:
            continue
        if secname.get(sec - 1) == ".data":
            syms[vm.group(2).lstrip("_")] = int(vm.group(1), 16)
    return dsize, syms


@app.callback(invoke_without_command=True)
def main(
    data_metadata: Path = typer.Option(
        Path("src/rebrew-data.toml"), "--data-metadata", help="Data metadata toml path"
    ),
    limit: int = typer.Option(15, "--limit", help="Max misplaced symbols to print"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build-then-compare: .data symbol VAs of the current build vs the metadata."""
    root = Path.cwd()
    metadata = data_metadata if data_metadata.is_absolute() else root / data_metadata
    if not metadata.exists():
        error_exit(f"data metadata not found: {metadata}")
    dll = root / "build" / "server.dll"
    if not dll.exists():
        error_exit("build/server.dll not found — build the project first")
    data_va = _data_section_va(dll)
    expected = _expected(root, metadata)

    here: dict[str, int] = {}
    tot = 0
    for obj in _link_objects(root):
        dsize, syms = _obj_data_symbols(obj)
        for sym, off in syms.items():
            here.setdefault(sym, data_va + tot + off)
        tot += dsize

    good = bad = 0
    bads: list[tuple[str, int, int]] = []
    for sym, addr in here.items():
        if sym in expected:
            if addr == expected[sym]:
                good += 1
            else:
                bad += 1
                bads.append((sym, expected[sym], addr))
    bads.sort(key=lambda t: -abs(t[1] - t[2]))

    if json_output:
        json_print(
            {
                "symbols": len(here),
                "matched": good + bad,
                "correct": good,
                "misplaced": bad,
                "misplaced_list": [
                    {"symbol": s, "expected": f"0x{e:x}", "actual": f"0x{a:x}", "delta": a - e}
                    for s, e, a in bads[:limit]
                ],
            }
        )
        return
    console.print(
        f"symbols: {len(here)}  toml-matched: {good + bad}  correct-VA: {good}  misplaced: {bad}"
    )
    for sym, exp, act in bads[:limit]:
        console.print(f"  {sym:32} exp {exp:#010x}  our {act:#010x}  d {act - exp:+#x}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
