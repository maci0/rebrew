"""lib-match — byte-compare reversed functions against linked static libraries.

Statically linked library code sits in the target's .text looking exactly like
game code, and a decompiler names it ``fcn_XXXX`` like anything else. Reversing
it is wasted effort: the linker supplies those bytes anyway. The existing
detectors do not settle it:

- ``rebrew flirt`` matches short byte signatures against prebuilt .pat files.
  A signature set built from a different library build misses real matches
  (measured: 9 of 68 CRT functions on one MSVC6 project), and short patterns
  cannot cover every function.
- ``rebrew crt-match`` compares against reference *source*, which exists only
  for the CRT/zlib families.

This command compares **whole function bodies** against the archives the
project actually links (.lib / .a), masking each object's relocation slots.
Whatever is identical outside those slots is library code. That is what a
linked-in object looks like, so the check has no false negatives from naming
or signature coverage.

Two details matter, both learned the hard way:

- MSVC marks CRT helpers such as ``_initterm`` and ``_parse_cmdline`` static
  (COFF storage class 3). They never appear in the archive symbol index, so an
  index built from external symbols alone reports them absent. The archive
  index here comes from ``gen_flirt_pat.parse_coff_obj``, which covers both
  classes.
- A body that is mostly relocation slots (a pointer table such as
  ``__sys_errlist``) "matches" anything once its slots are masked. Candidates
  must be at least half fixed bytes.

Usage::

    rebrew lib-match --lib LIBCMT.LIB                  # scan all reversed funcs
    rebrew lib-match --lib LIBCMT.LIB --va 0x1001a7f7  # one function
    rebrew lib-match --lib a.lib --lib b.lib --allow libcode_allowlist.txt

Exit status is 0 when nothing matches, 1 when a reversed function's bytes come
from one of the given libraries, 2 on config/library errors, so this works as
a pre-commit or CI gate.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.binary_loader import extract_raw_bytes
from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    EXIT_OK,
    TargetOption,
    error_exit,
    json_print,
    require_config,
)
from rebrew.gen_flirt_pat import parse_archive, parse_coff_obj
from rebrew.utils import container_runtime

console = Console(stderr=True)

MIN_BYTES = 8
MIN_FIXED_FRACTION = 0.5
PREFIX_BYTES = 32

Index = dict[str, list[tuple[str, bytes, set[int]]]]

app = typer.Typer(
    help=(
        "Byte-compare reversed functions against linked static libraries "
        "(.lib/.a). Flags code the linker supplies, so it is not worth reversing."
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
)


def index_library(path: Path) -> Index:
    """Index every code symbol in *path* by name -> [(object, body, relocs)]."""
    index: Index = {}
    try:
        members = parse_archive(str(path))
        for _member_name, obj in members:
            for sym, code, relocs in parse_coff_obj(obj):
                index.setdefault(sym, []).append((path.name, code, relocs))
    except Exception as exc:  # bad archive / unparsable member
        error_exit(f"cannot index {path}: {exc}", code=EXIT_ERROR)
    return index


def match_bytes(index: Index, data: bytes) -> tuple[str, str] | None:
    """Return ``(symbol, object)`` when *data* is a library body, else None."""
    if len(data) < MIN_BYTES:
        return None
    for sym, entries in index.items():
        for obj_name, body, relocs in entries:
            if len(body) < len(data):
                continue
            # Only reloc offsets inside the compared window mask a byte here;
            # relocs past len(data) (a longer library body) must not make the
            # mostly-relocation guard stricter than the comparison itself.
            fixed = {i for i in range(len(data)) if i not in relocs}
            if len(fixed) < MIN_FIXED_FRACTION * len(data):
                continue  # a mostly-relocation table trivially matches anything
            if all(data[i] == body[i] for i in fixed):
                return sym, obj_name
    return None


def _merge_libraries(libs: list[Path]) -> Index:
    """Index each library, merging duplicate symbol names across archives."""
    merged: Index = {}
    for p in libs:
        for sym, entries in index_library(p).items():
            merged.setdefault(sym, []).extend(entries)
    return merged


def load_allowlist(path: Path | None, *, json_mode: bool = False) -> set[int]:
    """Parse a ``#``-comment allow-list of hex VAs (one per line).

    BOM-safe: a file saved with a UTF-8 BOM would otherwise make the first
    entry ``"\\ufeff0x..."`` and crash ``int``.  A malformed entry is a user
    error, reported via ``error_exit`` rather than an uncaught ``ValueError``.
    """
    if path is None:
        return set()
    out: set[int] = set()
    for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            out.add(int(line, 16))
        except ValueError:
            error_exit(f"invalid allow-list entry {line!r} in {path}", json_mode=json_mode)
    return out


def _findings(cfg: Any, index: Index, allow: set[int]) -> list[dict[str, str]]:
    from rebrew.catalog.loaders import scan_reversed_dir

    found: list[dict[str, str]] = []
    for entry in scan_reversed_dir(cfg.reversed_dir, cfg=cfg):
        module = getattr(entry, "module", "") or ""
        va = int(getattr(entry, "va", 0) or 0)
        if not module or not va or va in allow:
            continue
        # A marker of GLOBAL/DATA is not a reversed function body.
        if getattr(entry, "marker_type", "FUNCTION") not in ("FUNCTION", "STUB"):
            continue
        try:
            data = extract_raw_bytes(cfg.target_binary, va, entry.size or PREFIX_BYTES)
        except Exception:
            continue
        hit = match_bytes(index, data)
        if hit is None and (entry.size or 0) > PREFIX_BYTES:
            # A wrong SIZE in the metadata overruns the function and hides a
            # real match; retry on a fixed prefix.
            try:
                hit = match_bytes(index, extract_raw_bytes(cfg.target_binary, va, PREFIX_BYTES))
            except Exception:
                hit = None
        if hit is not None:
            sym, obj_name = hit
            found.append(
                {
                    "va": f"0x{va:08x}",
                    "module": module,
                    "file": entry.filepath,
                    "symbol": sym,
                    "object": obj_name,
                }
            )
    return found


#: Path substring that marks a source-vendored library tree in a build database.
REFERENCES_MARKER = "/references/"

#: Default build database, relative to the project root (CMake's export).
COMPILE_COMMANDS_DEFAULT = Path("build") / "compile_commands.json"


def index_objects(objects: list[Path]) -> Index:
    """Index loose COFF ``.obj`` files the way ``index_library`` indexes an archive.

    A library vendored as source (built from a ``references/`` tree) never
    ships as a ``.LIB``, so a function reversed out of one is invisible to the
    archive scan.  Each entry's object name is the file name, so a finding
    still says which object the bytes came from.  An unreadable or unparsable
    object is skipped with a note rather than failing the whole scan.
    """
    index: Index = {}
    for path in objects:
        try:
            symbols = parse_coff_obj(path.read_bytes())
        except (OSError, ValueError) as exc:
            console.print(f"[yellow]skipping unreadable object {path}: {exc}[/yellow]")
            continue
        for sym, code, relocs in symbols:
            index.setdefault(sym, []).append((path.name, code, relocs))
    return index


def vendored_objects(
    compile_commands: Path,
    root: Path,
    *,
    marker: str = REFERENCES_MARKER,
) -> list[Path]:
    """Objects the build produces from a source-vendored library subtree.

    The list comes from the build database rather than a glob over the build
    directory: a stale object whose source was dropped would otherwise report
    as a duplicate of the project's own source.  A missing or malformed
    database yields no objects, and so does an entry with no ``/Fo`` output.
    """
    try:
        entries = json.loads(compile_commands.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(entries, list):
        return []
    found: list[Path] = []
    for entry in entries:
        if not isinstance(entry, dict) or marker not in str(entry.get("file", "")):
            continue
        match = re.search(r"/Fo(\S+)", str(entry.get("command", "")))
        if match is None:
            continue
        produced = Path(match.group(1))
        if not produced.is_absolute():
            produced = Path(str(entry.get("directory") or root)) / produced
        if produced.is_file():
            found.append(produced)
    return found


def stock_lib_source(profile: str, name: str) -> tuple[str, str]:
    """``(image, in-image path)`` of a stock archive from *profile*'s image.

    Both halves come from the registry: the image tag, and the container tool
    directory whose sibling ``Lib`` holds the archives (the derivation
    ``image_msvc_env`` already uses).  Nothing here hardcodes an image or a
    path, so a service pack that moves its tree cannot leave a check pointing
    at a directory that does not exist.
    """
    from rebrew.toolchain import ToolchainError, get_toolchain

    spec = get_toolchain(profile)
    if spec.image is None:
        raise ToolchainError(f"profile {profile!r} is host-only: no image to extract from")
    if not spec.tool_root:
        raise ToolchainError(
            f"profile {profile!r} declares no container tool_root, so its Lib dir cannot be derived"
        )
    return spec.image, str(Path(spec.tool_root).parent / "Lib" / name)


def stock_lib_cache(root: Path, name: str) -> Path:
    """Where a stock archive is cached: ``.scratch/<stem>_stock<suffix>``."""
    return root / ".scratch" / f"{Path(name).stem.lower()}_stock{Path(name).suffix}"


def ensure_stock_lib(dest: Path, *, profile: str, name: str) -> bool:
    """Extract *name* from the profile's image into *dest* when it is absent.

    Returns False when the container runtime is unavailable, which is how a
    machine without it skips the check instead of failing the gate.  A copy
    that fails with the runtime present is an error rather than a skip: it
    means the image does not carry the archive where its spec says it does.
    """
    from rebrew.toolchain import ToolchainError

    if dest.is_file():
        return True
    runtime = container_runtime()
    if shutil.which(runtime) is None:
        return False
    image, source = stock_lib_source(profile, name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            runtime,
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            "-v",
            f"{dest.parent}:/out",
            image,
            "-c",
            'cp "$1" "/out/$2"',
            "sh",
            source,
            dest.name,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0 or not dest.is_file():
        raise ToolchainError(
            f"cannot extract {name} from {image}: {result.stderr.strip() or 'no copy was written'}"
        )
    return True


def assert_library_is_stock(path: Path, *, profile: str, name: str) -> None:
    """Refuse *path* when it differs from the image's copy of *name*.

    One container run hashes both files, so the image's archive and the local
    copy are compared by the same tool.  An archive that was hand-edited (say,
    objects stripped to make a link succeed) fails here instead of quietly
    redefining what "library code" means, and a run that does not hash both
    files is an error rather than a silent pass.  An unavailable runtime
    skips, matching ``ensure_stock_lib``.
    """
    runtime = container_runtime()
    if shutil.which(runtime) is None:
        return
    image, source = stock_lib_source(profile, name)
    result = subprocess.run(
        [
            runtime,
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            "-v",
            f"{path.parent}:/out",
            image,
            "-c",
            'md5sum "$1" "/out/$2"',
            "sh",
            source,
            path.name,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    digests = [line.split()[0] for line in result.stdout.splitlines() if line.strip()]
    if len(digests) != 2:
        error_exit(
            f"cannot verify {path.name} against {image} ({source}): "
            f"{result.stderr.strip() or 'the image did not hash both files'}",
            code=EXIT_ERROR,
        )
    if digests[0] != digests[1]:
        error_exit(
            f"{path} differs from the toolchain's stock {name} in {image}. The check exists "
            "because a hand-edited archive makes library code look like target code; delete the "
            "cached copy to re-extract it, or drop --stock-lib for this run.",
            code=EXIT_ERROR,
        )


@app.callback(invoke_without_command=True)
def main(
    lib: list[Path] | None = typer.Option(
        None,
        "--lib",
        help="Static library to check against (repeatable).",
    ),
    stock_lib: list[str] | None = typer.Option(
        None,
        "--stock-lib",
        help=(
            "Stock archive from the project toolchain's image (repeatable), e.g. LIBCMT.LIB. "
            "Cached under .scratch/, extracted when missing, refused when it differs from the "
            "image's copy."
        ),
    ),
    compile_commands: Path | None = typer.Option(
        None,
        "--compile-commands",
        help=(
            "Build database used to index objects built from a source-vendored tree "
            "(default: build/compile_commands.json; skipped when absent)."
        ),
    ),
    va: str | None = typer.Option(
        None, "--va", help="Check a single VA (hex) instead of every reversed function."
    ),
    allow: Path | None = typer.Option(
        None, "--allow", help="File of VAs known library code, one hex VA per line (# comments)."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Flag reversed functions whose bytes come from a linked library."""
    from rebrew.toolchain import ToolchainError

    cfg = require_config(target=target, json_mode=json_output)

    archives = list(lib or [])
    for name in stock_lib or []:
        cached = stock_lib_cache(cfg.root, name)
        try:
            if not ensure_stock_lib(cached, profile=cfg.compiler_profile, name=name):
                console.print(
                    f"[yellow]skipping {name}: {container_runtime()} is not available[/yellow]"
                )
                continue
            assert_library_is_stock(cached, profile=cfg.compiler_profile, name=name)
        except ToolchainError as exc:
            error_exit(str(exc), json_mode=json_output, code=EXIT_ERROR)
        archives.append(cached)

    objects = vendored_objects(compile_commands or (cfg.root / COMPILE_COMMANDS_DEFAULT), cfg.root)
    if not archives and not objects:
        error_exit(
            "nothing to check against: pass --lib (an archive the target links), --stock-lib "
            "(a stock archive from the toolchain's image, e.g. LIBCMT.LIB), or build the "
            "project with --compile-commands so a source-vendored library can be indexed.",
            json_mode=json_output,
            code=EXIT_ERROR,
        )
    index = _merge_libraries(archives)
    for sym, entries in index_objects(objects).items():
        index.setdefault(sym, []).extend(entries)

    if va is not None:
        from rebrew.cli import parse_va
        from rebrew.metadata import get_entry

        va_int = parse_va(va)
        module = getattr(cfg, "marker", None) or "SERVER"
        size = (get_entry(cfg.metadata_dir, va_int, module) or {}).get("size") or 0
        data = extract_raw_bytes(cfg.target_binary, va_int, size or PREFIX_BYTES)
        hit = match_bytes(index, data)
        if hit is None and (size or 0) > PREFIX_BYTES:
            hit = match_bytes(index, extract_raw_bytes(cfg.target_binary, va_int, PREFIX_BYTES))
        if hit is not None:
            sym, obj_name = hit
            if json_output:
                json_print(
                    {"va": f"0x{va_int:08x}", "library": True, "symbol": sym, "object": obj_name}
                )
            else:
                console.print(
                    f"[yellow]0x{va_int:08x} is library code:[/yellow] {sym} in {obj_name}"
                )
                console.print("Do not reverse it; the linker supplies these bytes.")
            raise typer.Exit(code=EXIT_MISMATCH)
        if json_output:
            json_print({"va": f"0x{va_int:08x}", "library": False})
        else:
            console.print(
                f"[green]0x{va_int:08x} is not in the given libraries.[/green] Safe to reverse."
            )
        raise typer.Exit(code=EXIT_OK)

    found = _findings(cfg, index, load_allowlist(allow, json_mode=json_output))
    if json_output:
        json_print({"findings": found, "count": len(found)})
    else:
        if not found:
            console.print("[green]No reversed function matches a linked library.[/green]")
        else:
            console.print("Reversed functions whose bytes come from a linked library:\n")
            for f in found:
                console.print(f"  [yellow]{f['va']}[/yellow]  {f['file']}")
                console.print(f"              {f['symbol']} in {f['object']}")
            console.print(
                f"\n{len(found)} function(s). These do not need reversing: the linker supplies "
                "them. Delete the source, or add the VA to the --allow file with a reason "
                "if the file must stay for link reasons."
            )
    raise typer.Exit(code=EXIT_MISMATCH if found else EXIT_OK)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
