"""link-sweep — find which LINK options reproduce the reference PE header.

Most PE header fields map 1:1 onto MSVC6 LINK options (``/BASE``, ``/ALIGN``,
``/SUBSYSTEM``, ``/STACK``, ``/HEAP`` — see :func:`rebrew.gen_layout.derive_link_options`).
For the residuals (e.g. FileAlignment, which VC6's ``/ALIGN`` does not raise
from its 0x200 default to the original's 0x1000) it is not obvious which
option, if any, reproduces them — or whether the field is linker-stamped and
only reachable by the post-link metadata fix.

This command answers that empirically: link the project's objects with each
candidate option set, diff the resulting header fields against the reference,
and report which fields each candidate fixes and which resist every candidate
(stamp-only → belongs in the final metadata fix).

The link command is taken from ``build/CMakeFiles/*/link.txt`` when present
(``/out:`` is redirected to a scratch file and the candidate options are
appended before the library list), or from ``--link-cmd`` (a template with
``{options}`` and ``{out}`` placeholders).

Usage::

    rebrew link-sweep --target server.dll
    rebrew link-sweep --target server.dll --link-cmd "link.exe @objs.rsp /out:{out} {options}"
    rebrew link-sweep --target server.dll --json
"""

from __future__ import annotations

import atexit
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.gen_layout import _parse_pe, derive_link_options

console = Console(stderr=True)

app = typer.Typer(help="Sweep LINK options to reproduce the reference PE header.")

#: Header fields the sweep compares, in a stable order.
_FIELDS = [
    ("e_lfanew", "u32@0x3c"),
    ("Machine", "u16@coff+0"),
    ("NumberOfSections", "u16@coff+2"),
    ("TimeDateStamp", "u32@coff+4"),
    ("Characteristics", "u16@coff+18"),
    ("Magic", "u16@opt+0"),
    ("SizeOfCode", "u32@opt+4"),
    ("SizeOfInitData", "u32@opt+8"),
    ("SizeOfUninitData", "u32@opt+12"),
    ("AddressOfEntryPoint", "u32@opt+16"),
    ("BaseOfCode", "u32@opt+20"),
    ("BaseOfData", "u32@opt+24"),
    ("ImageBase", "u32@opt+28"),
    ("SectionAlignment", "u32@opt+32"),
    ("FileAlignment", "u32@opt+36"),
    ("OSVersion", "u8@opt+40:u8@opt+41"),
    ("SubsystemVersion", "u8@opt+48:u8@opt+49"),
    ("SizeOfImage", "u32@opt+56"),
    ("SizeOfHeaders", "u32@opt+60"),
    ("CheckSum", "u32@opt+64"),
    ("Subsystem", "u16@opt+68"),
    ("DllCharacteristics", "u16@opt+70"),
    ("StackReserve", "u32@opt+72"),
    ("StackCommit", "u32@opt+76"),
    ("HeapReserve", "u32@opt+80"),
    ("HeapCommit", "u32@opt+84"),
]


def _read_fields(path: Path) -> dict[str, int]:
    d = path.read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    coff = e + 4
    opt = coff + 20
    out: dict[str, int] = {}

    def u32(off: int) -> int:
        return int(struct.unpack_from("<I", d, off)[0])

    def u16(off: int) -> int:
        return int(struct.unpack_from("<H", d, off)[0])

    def u8(off: int) -> int:
        return d[off]

    for name, spec in _FIELDS:
        parts = spec.split(":")
        vals = []
        for p in parts:
            kind, loc = p.split("@")
            if loc.startswith("0x"):
                off = int(loc, 16)
            elif loc.startswith("coff+"):
                off = coff + int(loc[5:])
            elif loc.startswith("opt+"):
                off = opt + int(loc[4:])
            else:
                raise ValueError(loc)
            vals.append({"u32": u32, "u16": u16, "u8": u8}[kind](off))
        out[name] = vals[0] if len(vals) == 1 else (vals[0] << 8) | vals[1]
    return out


def _discover_link_cmd() -> tuple[Path, str] | None:
    """Find (workdir, command) from a CMake ``link.txt``, or None."""
    hits = (
        sorted(Path("build/CMakeFiles").glob("*/link.txt"))
        if Path("build/CMakeFiles").is_dir()
        else []
    )
    if not hits:
        hits = sorted(Path("build").glob("CMakeFiles/*/link.txt"))
    if not hits:
        return None
    txt = hits[0].read_text(encoding="utf-8").strip()
    # redirect /out: to {out}; strip /pdb: (wine link may reject a dup pdb)
    txt = re.sub(r"/out:[^ ]+", "/out:{out}", txt)
    txt = re.sub(r"/pdb:[^ ]+", "/pdb:{out}.pdb", txt)
    txt = f"{txt} {{options}}"
    return Path("build"), txt


@dataclass
class _Candidate:
    name: str
    options: list[str]


def _candidates(pe: dict[str, Any]) -> list[_Candidate]:
    """Delta-derived base + explicit probes of the uncertain dimensions.

    The base only carries options the reference deviates from the VC6
    defaults on (see gen_layout.derive_link_options).  The probes then vary
    one knob at a time — the alignment family in particular, since adding
    ``/ALIGN`` can *break* fields the plain default gets right (FileAlignment
    drops to 0x200, SizeOfHeaders shrinks).
    """
    opts, _ = derive_link_options(pe)

    def plus(*extra: str) -> list[str]:
        # append, dropping any base option with the same /PREFIX: so a probe
        # cleanly replaces rather than duplicates
        out = list(opts)
        for e in extra:
            prefix = e.split(":", 1)[0]
            out = [o for o in out if o.split(":", 1)[0] != prefix]
            out.append(e)
        return out

    return [
        _Candidate("base", opts),
        _Candidate("release", plus("/RELEASE")),
        _Candidate("align_0x1000", plus("/ALIGN:0x1000")),
        _Candidate("align_0x200", plus("/ALIGN:0x200")),
        _Candidate("align_0x10000", plus("/ALIGN:0x10000")),
        _Candidate("subsys_ver", plus("/SUBSYSTEM:WINDOWS,4.0")),
        _Candidate("merge_rdata", plus("/MERGE:.rdata=.data")),
    ]


def main(
    target: str | None = TargetOption,
    link_cmd: str | None = typer.Option(
        None,
        "--link-cmd",
        help="Link command template with {options} and {out} placeholders "
        "(default: auto-discover build/CMakeFiles/*/link.txt)",
    ),
    cwd: Path | None = typer.Option(
        None, "--cwd", help="Working directory for the link command (default: the build dir)"
    ),
    keep: bool = typer.Option(False, "--keep", help="Keep scratch DLLs in the temp dir"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Link the project's objects with candidate option sets and diff headers."""
    cfg = require_config(target)
    if not cfg.target_binary.exists():
        error_exit(f"binary not found: {cfg.target_binary}")

    if link_cmd:
        cmd_tpl, workdir = link_cmd, (cwd or Path("."))
    else:
        found = _discover_link_cmd()
        if found is None:
            error_exit("no build/CMakeFiles/*/link.txt found — pass --link-cmd")
        workdir, cmd_tpl = found
        if cwd:
            workdir = cwd

    _, _, _, pe = _parse_pe(cfg.target_binary.read_bytes())
    ref = _read_fields(cfg.target_binary)
    candidates = _candidates(pe)

    results: list[dict[str, Any]] = []
    # Per-run scratch dir with an unpredictable name: a fixed shared dir in
    # the system temp dir would let another local user pre-create/symlink the
    # DLL path (the linker follows it), clobber a concurrent sweep, and leak
    # partial DLLs from failed links forever.
    scratch_dir = Path(tempfile.mkdtemp(prefix="rebrew-linksweep-"))
    if not keep:
        atexit.register(shutil.rmtree, scratch_dir, True)
    for cand in candidates:
        out = scratch_dir / f"{cand.name}.dll"
        cmd = cmd_tpl.format(options=" ".join(cand.options), out=out)
        try:
            proc = subprocess.run(
                shlex.split(cmd), cwd=workdir, capture_output=True, text=True, timeout=300
            )
        except subprocess.TimeoutExpired:
            # One hung link must not kill the sweep — record it and move on.
            results.append(
                {
                    "candidate": cand.name,
                    "options": cand.options,
                    "link_failed": True,
                    "stderr": f"link timed out after 300s: {cmd}",
                }
            )
            continue
        if not out.exists():
            results.append(
                {
                    "candidate": cand.name,
                    "options": cand.options,
                    "link_failed": True,
                    "stderr": (proc.stderr or "")[-400:],
                }
            )
            continue
        fields = _read_fields(out)
        diffs = {k: (ref[k], fields[k]) for k in ref if ref[k] != fields.get(k)}
        if not keep:
            out.unlink(missing_ok=True)
        results.append(
            {
                "candidate": cand.name,
                "options": cand.options,
                "link_failed": False,
                "diff_count": len(diffs),
                "diffs": diffs,
            }
        )

    if json_output:
        json_print(
            {
                "reference": str(cfg.target_binary),
                "scratch_dir": str(scratch_dir),
                "results": results,
            }
        )
        return

    # render
    stamp_only = set(ref)
    for r in results:
        if r.get("link_failed"):
            continue
        stamp_only &= set(r["diffs"])
    table = Table(title="link-sweep — header fields differing from the reference")
    table.add_column("candidate")
    table.add_column("diffs", justify="right")
    table.add_column("fields")
    for r in results:
        if r.get("link_failed"):
            table.add_row(r["candidate"], "LINK FAILED", (r.get("stderr") or "")[:80])
            continue
        names = ", ".join(r["diffs"]) if r["diffs"] else "(none)"
        table.add_row(r["candidate"], str(r["diff_count"]), names)
    console.print(table)
    # classify the stamp-only set: section-derived fields are fixed by the
    # *objects* (data-restore/BSS work), not by link options or header stamps.
    _SECTION_DERIVED = {
        "NumberOfSections",
        "SizeOfCode",
        "SizeOfInitData",
        "SizeOfUninitData",
        "AddressOfEntryPoint",
        "BaseOfCode",
        "BaseOfData",
        "SizeOfImage",
    }
    derived = sorted(stamp_only & _SECTION_DERIVED)
    stamped = sorted(stamp_only - _SECTION_DERIVED)
    if derived:
        console.print("\n[yellow]Section-derived fields (differ in every candidate):[/]")
        console.print("  " + ", ".join(derived))
        console.print("  → fixed by the object content (.data/BSS layout), not link options.")
    if stamped:
        console.print("\n[yellow]Link-stamped fields (differ in every candidate):[/]")
        console.print("  " + ", ".join(stamped))
        console.print("  → belong in the final metadata fix, not the link line.")
    if not stamp_only:
        console.print("\n[green]All compared fields reproduced by at least one candidate.[/]")
    if keep:
        console.print(f"\n[dim]Scratch DLLs kept in: {scratch_dir}[/]")


def main_entry() -> None:
    app()


if __name__ == "__main__":
    main_entry()
