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
project's layout package (``layout/<target>/rebrew-layout.toml``).

Usage:
    rebrew calibrate-bss [--stub src/link_stubs.c] [--target-vs 0x174059c] [--max-iters 8]
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import subprocess
import tempfile
import tomllib
from pathlib import Path

import typer
from rich.console import Console

from rebrew.cli import TargetOption, error_exit, json_print
from rebrew.pe_headers import find_section
from rebrew.utils import atomic_write_text, load_tomllib, read_source_text, run_process_group
from rebrew.workspace import walk_up_to_root

console = Console(stderr=True)

app = typer.Typer(
    help="Calibrate a BSS tail pad so the raw link's .data VirtualSize matches the reference.",
    rich_markup_mode="rich",
)


def _layout_data_vs(root: Path, target: str | None = None) -> int | None:
    """Reference ``.data`` VirtualSize from the layout package.

    *target* selects its ``layout/<target>/`` package; without it the
    project's ``default_target`` applies (falling back to a package scan).
    """
    from rebrew.layout_meta import read_layout_geometry

    if target:
        targets = [target]
    else:
        default = ""
        with contextlib.suppress(OSError, tomllib.TOMLDecodeError):
            default = str(
                load_tomllib(root / "rebrew-project.toml").get("project", {}).get("default_target")
                or ""
            )
        targets = [default] if default else []
        targets += [
            p.parent.name
            for p in sorted((root / "layout").glob("*/rebrew-layout.toml"))
            if p.parent.name not in targets
        ]
    # Default target first — scanning every target and returning the first
    # .data VS silently calibrated against the wrong binary when the project
    # has several targets.
    for candidate in targets:
        with contextlib.suppress(ValueError):
            base, _raw_end, section_end = read_layout_geometry(root, candidate)
            return section_end - base
    return None


def find_link_cmd(root: Path, *, json_mode: bool = False) -> tuple[Path, str, Path]:
    """(link cwd, link template, target dir) from build/CMakeFiles/*/link.txt."""
    hits = sorted((root / "build/CMakeFiles").glob("*/link.txt"))
    if not hits:
        error_exit(
            "no build/CMakeFiles/*/link.txt found — build the project first",
            json_mode=json_mode,
        )
    txt = hits[0].read_text(encoding="utf-8").strip()
    txt = re.sub(r"/out:[^ ]+", "/out:{out}", txt, flags=re.IGNORECASE)
    txt = re.sub(r"/pdb:[^ ]+", "/pdb:{out}.pdb", txt, flags=re.IGNORECASE)
    txt = f"{txt} {{options}}"
    return root / "build", txt, hits[0].parent


def read_data_vs(path: Path) -> int:
    """The ``.data`` section VirtualSize of a PE file."""
    section = find_section(path.read_bytes(), ".data")
    if section is None:
        raise ValueError("no .data section in the linked binary")
    return section.virtual_size


@app.callback(invoke_without_command=True)
def main(
    stub: Path = typer.Option(Path("src/link_stubs.c"), "--stub", help="Stub TU holding the tail"),
    symbol: str = typer.Option("g_bss_tail", "--symbol", help="Tail array symbol name"),
    target_vs: str | None = typer.Option(
        None, "--target-vs", help="Target .data VirtualSize (default: the layout metadata's)"
    ),
    max_iters: int = typer.Option(8, "--max-iters", help="Max calibration iterations"),
    compile_cmd: str = typer.Option(
        "rebrew-cmake-cl", "--compile-cmd", help="Command to recompile the stub TU"
    ),
    cflags: str = typer.Option("/O2 /Gd", "--cflags", help="Flags for the stub compile"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Calibrate *symbol* in *stub* so the raw link's .data VirtualSize == *target_vs*."""
    root = walk_up_to_root(Path.cwd())
    if root is None:
        error_exit("no rebrew-project.toml found above the cwd", json_mode=json_output)
    stub = stub if stub.is_absolute() else root / stub
    if not stub.exists():
        error_exit(f"stub file not found: {stub}", json_mode=json_output)
    if target_vs is None:
        target_vs_int = _layout_data_vs(root, target=target)
        if target_vs_int is None:
            error_exit(
                "no target VS given and no .data vs in the layout metadata", json_mode=json_output
            )
        target_vs_int = int(target_vs_int)
    else:
        try:
            target_vs_int = int(target_vs, 0)
        except ValueError:
            error_exit(
                f"--target-vs must be an integer-like value (got {target_vs!r})",
                json_mode=json_output,
            )

    if max_iters < 1:
        error_exit("--max-iters must be at least 1", json_mode=json_output)

    tail_re = re.compile(rf"{symbol}\[\s*0x([0-9A-Fa-f]+)\s*\]")
    # Stub is a C source: use the shared detector so a CP1252/Shift-JIS comment
    # survives the calibrate rewrite (utf-8-only read+write would U+FFFD it).
    stub_text, stub_encoding = read_source_text(stub)
    if not tail_re.search(stub_text):
        error_exit(f"{symbol}[0x..] not found in {stub}", json_mode=json_output)

    if dry_run:
        if json_output:
            json_print(
                {
                    "target_vs": hex(target_vs_int),
                    "symbol": symbol,
                    "stub": str(stub),
                    "dry_run": True,
                }
            )
        else:
            console.print(
                f"[cyan]dry-run:[/cyan] would calibrate {symbol} in {stub} "
                f"to .data VS=0x{target_vs_int:x}"
            )
        return

    link_cwd, cmd_tpl, target_dir = find_link_cmd(root, json_mode=json_output)
    # Unpredictable scratch name in the shared temp dir: a fixed
    # "rebrew-calibrate-bss.dll" would let any local user pre-create/symlink
    # the path (the linker follows it) or swap the DLL between iterations and
    # poison the calibration, and concurrent runs would clobber each other.
    fd, scratch_name = tempfile.mkstemp(prefix="rebrew-calibrate-bss-", suffix=".dll")
    os.close(fd)
    scratch = Path(scratch_name)

    iters: list[dict[str, int]] = []
    # The loop rewrites the stub tail in place before each relink; a failed
    # calibration must not leave a wrong pad behind, so snapshot and restore.
    original_stub = stub_text
    try:
        for it in range(max_iters):
            # Quote the scratch path before shlex.split so a space-bearing
            # temp dir cannot re-split the argv; shell=True is refused so
            # metacharacters in CMake's link.txt cannot execute.
            cmd = cmd_tpl.format(out=shlex.quote(str(scratch)), options="")
            try:
                # Group kill: a wrapper's linker must not outlive a timeout.
                run_process_group(
                    shlex.split(cmd), cwd=link_cwd, capture_output=True, timeout=600
                ).check_returncode()
            except subprocess.TimeoutExpired:
                error_exit(
                    f"raw link timed out after 600s (iter {it}): {cmd}", json_mode=json_output
                )
            except subprocess.CalledProcessError as exc:
                # capture_output swallows the linker's stderr — surface it, or the
                # failure is an opaque traceback with no diagnostic.
                stderr = (
                    exc.stderr.decode("utf-8", errors="replace")[-400:].strip()
                    if exc.stderr
                    else ""
                )
                error_exit(
                    f"raw link failed (rc={exc.returncode}) on iter {it}: {stderr}",
                    json_mode=json_output,
                )
            vs = read_data_vs(scratch)
            delta = target_vs_int - vs
            iters.append({"iter": it, "vs": vs, "delta": delta})
            if delta == 0:
                break
            text, stub_encoding = read_source_text(stub)
            m = tail_re.search(text)
            if m is None:
                error_exit(f"{symbol}[0x..] not found in {stub}", json_mode=json_output)
            new_tail = int(m.group(1), 16) + delta
            if new_tail <= 0:
                error_exit(
                    f"tail would go non-positive ({new_tail:#x}) — manual fix needed",
                    json_mode=json_output,
                )
            atomic_write_text(
                stub,
                text[: m.start(1)] + f"{new_tail:x}" + text[m.end(1) :],
                encoding=stub_encoding,
            )
            obj = target_dir / stub.relative_to(root).with_suffix(".obj")
            try:
                run_process_group(
                    [compile_cmd, "/nologo", "/c", *cflags.split(), f"/Fo{obj}", str(stub)],
                    cwd=root,
                    capture_output=True,
                    timeout=300,
                ).check_returncode()
            except subprocess.TimeoutExpired:
                error_exit(
                    f"stub compile timed out after 300s: {compile_cmd}", json_mode=json_output
                )
            except subprocess.CalledProcessError as exc:
                stderr = (
                    exc.stderr.decode("utf-8", errors="replace")[-400:].strip()
                    if exc.stderr
                    else ""
                )
                error_exit(
                    f"stub compile failed (rc={exc.returncode}): {stderr}", json_mode=json_output
                )
        else:
            error_exit(
                f"did not converge in {max_iters} iterations (last delta {iters[-1]['delta']:+d})",
                json_mode=json_output,
            )
    except BaseException:
        atomic_write_text(stub, original_stub, encoding=stub_encoding)
        raise
    finally:
        scratch.unlink(missing_ok=True)

    if json_output:
        json_print({"target_vs": hex(target_vs_int), "symbol": symbol, "iters": iters})
    else:
        for row in iters:
            console.print(
                f"iter {row['iter']}: raw .data VS=0x{row['vs']:x} delta={row['delta']:+d}"
            )
        console.print(f"calibrated OK (target 0x{target_vs_int:x})")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
