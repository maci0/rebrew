"""calibrate-bss — size a BSS tail pad so the raw link's .data VirtualSize matches.

MSVC LINK's ``.data`` VirtualSize from zero-init stub globals + a tail pad
is not exactly predictable (per-symbol alignment, obj ``.bss`` interleaving,
the CRT <common> tail), so the tail size is calibrated empirically:

1. relink the project raw (reusing the CMake link command, ``/out``
   redirected to a scratch file);
2. measure the raw ``.data`` VirtualSize;
3. adjust the tail array in the stub file by the delta;
4. recompile the stub object and repeat until VS == the target.

The target VS defaults to the reference's ``.data`` VirtualSize from the
project's layout metadata (``[targets.<t>.layout]`` sections).

Usage:
    rebrew calibrate-bss [--stub src/link_stubs.c] [--target 0x174059c] [--max-iters 8]
"""

from __future__ import annotations

import os
import re
import struct
import subprocess
import tempfile
import tomllib
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import error_exit, json_print
from rebrew.config import walk_up_to_root

console = Console(stderr=True)

app = typer.Typer(
    help="Calibrate a BSS tail pad so the raw link's .data VirtualSize matches the reference.",
    rich_markup_mode="rich",
)


def _layout_data_vs(root: Path) -> int | None:
    try:
        with open(root / "rebrew-project.toml", "rb") as f:
            cfg = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    targets = cfg.get("targets", {})
    if not isinstance(targets, dict) or not targets:
        return None
    # Pick the DEFAULT target only — scanning every target and returning the
    # first .data VS silently calibrated against the wrong binary when the
    # project has several targets (link-review F7).
    default = cfg.get("default_target")
    if default is None or default not in targets:
        default = next(iter(targets))
    tcfg = targets[default]
    lay = tcfg.get("layout", {}) if isinstance(tcfg, dict) else {}
    for s in lay.get("sections", []):
        if s.get("name") == ".data":
            return int(s.get("vs", 0))
    return None


def find_link_cmd(root: Path) -> tuple[Path, str, Path]:
    """(link cwd, link template, target dir) from build/CMakeFiles/*/link.txt."""
    hits = sorted((root / "build/CMakeFiles").glob("*/link.txt"))
    if not hits:
        error_exit("no build/CMakeFiles/*/link.txt found — build the project first")
    txt = hits[0].read_text(encoding="utf-8").strip()
    txt = re.sub(r"/out:[^ ]+", "/out:{out}", txt, flags=re.IGNORECASE)
    txt = re.sub(r"/pdb:[^ ]+", "/pdb:{out}.pdb", txt, flags=re.IGNORECASE)
    txt = f"{txt} {{options}}"
    return root / "build", txt, hits[0].parent


def read_data_vs(path: Path) -> int:
    """The ``.data`` section VirtualSize of a PE file."""
    d = path.read_bytes()
    e = struct.unpack_from("<I", d, 0x3C)[0]
    n = struct.unpack_from("<H", d, e + 6)[0]
    optsz = struct.unpack_from("<H", d, e + 20)[0]
    sh = e + 24 + optsz
    for i in range(n):
        h = sh + i * 40
        if d[h : h + 8].rstrip(b"\0") == b".data":
            vals: tuple[int, int, int, int] = struct.unpack_from("<IIII", d, h + 8)
            return vals[0]
    raise ValueError("no .data section in the linked binary")


def _stub_obj(target_dir: Path, stub: Path, root: Path) -> Path:
    rel = stub.relative_to(root).with_suffix(".obj")
    return target_dir / rel


@app.callback(invoke_without_command=True)
def main(
    stub: Path = typer.Option(Path("src/link_stubs.c"), "--stub", help="Stub TU holding the tail"),
    symbol: str = typer.Option("g_bss_tail", "--symbol", help="Tail array symbol name"),
    target: str | None = typer.Option(
        None, "--target", help="Target .data VirtualSize (default: the layout metadata's)"
    ),
    max_iters: int = typer.Option(8, "--max-iters", help="Max calibration iterations"),
    compile_cmd: str = typer.Option(
        "rebrew-cmake-cl", "--compile-cmd", help="Command to recompile the stub TU"
    ),
    cflags: str = typer.Option("/O2 /Gd", "--cflags", help="Flags for the stub compile"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Calibrate *symbol* in *stub* so the raw link's .data VirtualSize == *target*."""
    root = walk_up_to_root(Path.cwd())
    if root is None:
        error_exit("no rebrew-project.toml found above the cwd")
    stub = stub if stub.is_absolute() else root / stub
    if not stub.exists():
        error_exit(f"stub file not found: {stub}")
    if target is None:
        target_vs = _layout_data_vs(root)
        if target_vs is None:
            error_exit("no target VS given and no .data vs in the layout metadata")
        target_vs = int(target_vs)
    else:
        target_vs = int(target, 0)

    tail_re = re.compile(rf"{symbol}\[\s*0x([0-9A-Fa-f]+)\s*\]")
    if not tail_re.search(stub.read_text(encoding="utf-8")):
        error_exit(f"{symbol}[0x..] not found in {stub}")

    link_cwd, cmd_tpl, target_dir = find_link_cmd(root)
    # Unpredictable scratch name in the shared temp dir: a fixed
    # "rebrew-calibrate-bss.dll" would let any local user pre-create/symlink
    # the path (the linker follows it) or swap the DLL between iterations and
    # poison the calibration, and concurrent runs would clobber each other.
    fd, scratch_name = tempfile.mkstemp(prefix="rebrew-calibrate-bss-", suffix=".dll")
    os.close(fd)
    scratch = Path(scratch_name)

    iters: list[dict[str, int]] = []
    try:
        for it in range(max_iters):
            cmd = cmd_tpl.format(out=scratch, options="")
            try:
                subprocess.run(
                    cmd, shell=True, cwd=link_cwd, check=True, capture_output=True, timeout=600
                )
            except subprocess.TimeoutExpired:
                error_exit(f"raw link timed out after 600s (iter {it}): {cmd}")
            except subprocess.CalledProcessError as exc:
                # capture_output swallows the linker's stderr — surface it, or the
                # failure is an opaque traceback with no diagnostic.
                stderr = exc.stderr.decode(errors="replace")[-400:].strip() if exc.stderr else ""
                error_exit(f"raw link failed (rc={exc.returncode}) on iter {it}: {stderr}")
            vs = read_data_vs(scratch)
            delta = target_vs - vs
            iters.append({"iter": it, "vs": vs, "delta": delta})
            if delta == 0:
                break
            text = stub.read_text(encoding="utf-8")
            m = tail_re.search(text)
            if m is None:
                error_exit(f"{symbol}[0x..] not found in {stub}")
            new_tail = int(m.group(1), 16) + delta
            if new_tail <= 0:
                error_exit(f"tail would go non-positive ({new_tail:#x}) — manual fix needed")
            stub.write_text(
                text[: m.start(1)] + f"{new_tail:x}" + text[m.end(1) :], encoding="utf-8"
            )
            obj = _stub_obj(target_dir, stub, root)
            try:
                subprocess.run(
                    [compile_cmd, "/nologo", "/c", *cflags.split(), f"/Fo{obj}", str(stub)],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    timeout=300,
                )
            except subprocess.TimeoutExpired:
                error_exit(f"stub compile timed out after 300s: {compile_cmd}")
            except subprocess.CalledProcessError as exc:
                stderr = exc.stderr.decode(errors="replace")[-400:].strip() if exc.stderr else ""
                error_exit(f"stub compile failed (rc={exc.returncode}): {stderr}")
        else:
            error_exit(f"did not converge in {max_iters} iterations (last delta {delta:+d})")
    finally:
        scratch.unlink(missing_ok=True)

    if json_output:
        json_print({"target": target_vs, "symbol": symbol, "iters": iters})
    else:
        for row in iters:
            print(f"iter {row['iter']}: raw .data VS=0x{row['vs']:x} delta={row['delta']:+d}")
        print(f"calibrated OK (target 0x{target_vs:x})")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
