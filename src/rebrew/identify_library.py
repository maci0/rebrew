"""identify_library.py — combined library-identification pass.

Runs the three existing identification backends against the target binary
and writes new ``library_*.h`` entries for uncovered functions, so CRT/zlib
library code is marked without manual triage:

1. **CRT source matching** (``crt_match``) — strongest: a reference source
   match carries a module and a confidence score.
2. **FLIRT** (``flirt``) — library function names from ``.sig``/``.pat``
   signatures (ambiguous matches are skipped, never guessed).
3. **IAT import stubs** (``imports.find_import_stubs``) — ``jmp [IAT]``
   thunks whose target API is the function identity.

Candidates are merged by VA with provenance ranking (CRT > FLIRT > import)
and only VAs with no existing FUNCTION/LIBRARY annotation are written, so the
command is safe to re-run (idempotent) and never overwrites a decompiled
function.  High-confidence CRT matches also get their ``SOURCE`` metadata
written (same rule as ``rebrew crt-match --fix-source``).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.cli import TargetOption, json_print, require_config

console = Console(stderr=True)

app = typer.Typer(
    help="Identify library functions (FLIRT + imports + CRT) into library_*.h.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew identify-library · · · · · · · Identify and write library entries\n\n"
        "  rebrew identify-library --dry-run · · Preview without writing\n\n"
        "  rebrew identify-library --json · · · · Machine-readable report\n\n"
        "[dim]Writes // LIBRARY: entries to library_<module>.h in the reversed "
        "directory; never touches annotated functions.[/dim]"
    ),
)

#: CRT API name prefixes → MSVCRT module (used when the backend does not
#: carry a module, i.e. FLIRT hits and import stubs).
_CRT_PREFIXES = (
    "mem",
    "str",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "fflush",
    "fprintf",
    "printf",
    "scanf",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "atoi",
    "atol",
    "atof",
    "abs",
    "labs",
    "qsort",
    "bsearch",
    "rand",
    "srand",
    "tolower",
    "toupper",
    "isalpha",
    "isdigit",
    "isalnum",
    "isspace",
    "islower",
    "isupper",
    "time",
    "localtime",
    "gmtime",
    "mktime",
    "clock",
    "exit",
    "abort",
    "atexit",
    "getenv",
    "putenv",
    "system",
    "assert",
    "signal",
    "raise",
    "sin",
    "cos",
    "tan",
    "sqrt",
    "pow",
    "floor",
    "ceil",
    "fabs",
    "exp",
    "log",
)

#: Provenance rank — CRT source match beats a FLIRT name beats an import thunk.
_KIND_RANK = {"crt": 3, "flirt": 2, "import": 1}


@dataclass(frozen=True)
class LibCandidate:
    """One identified library function."""

    va: int
    name: str
    module: str
    kind: str  # "crt" | "flirt" | "import"
    confidence: float
    source_ref: str = ""


#: zlib/zlib-adjacent API name prefixes → ZLIB module (FLIRT hits without
#: per-file attribution).
_ZLIB_PREFIXES = (
    "deflate",
    "inflate",
    "crc32",
    "adler32",
    "zlib",
    "compress",
    "uncompress",
    "gzopen",
    "gzread",
    "gzwrite",
    "gzclose",
    "gzgets",
    "gzputs",
    "gzseek",
    "gztell",
    "gzerror",
    "gzprintf",
    "gzdopen",
    "gzflush",
)

#: Sig-file stem (minus the _vcN suffix) → canonical module.
_SIG_FILE_MODULES = {
    "msvcrt": "MSVCRT",
    "libcmt": "MSVCRT",
    "libc": "MSVCRT",
    "libcpmt": "MSVCRT",
    "oldnames": "MSVCRT",
    "zlib": "ZLIB",
    "libz": "ZLIB",
}


def _infer_module(name: str, default: str) -> str:
    """Best-effort module for a bare API name (FLIRT/import backends)."""
    bare = name.lstrip("_")
    if bare.startswith(_CRT_PREFIXES):
        return "MSVCRT"
    if bare.startswith(_ZLIB_PREFIXES):
        return "ZLIB"
    return default


def _module_from_sig_file(filename: str, default: str) -> str:
    """Module attributed to a signature file by its name (e.g. msvcrt_vc6.pat).

    ``_vcN`` suffixes are stripped; known stems map to canonical modules
    (libcmt/msvcrt → MSVCRT, zlib → ZLIB); unknown stems become the uppercased
    stem (a ``foo_vc6.pat`` from a custom .lib → ``FOO``).
    """
    import re

    stem = Path(filename).stem.lower()
    stem = re.sub(r"_vc\d+$", "", stem)
    if stem in _SIG_FILE_MODULES:
        return _SIG_FILE_MODULES[stem]
    stem = re.sub(r"^lib", "", stem)
    if stem in _SIG_FILE_MODULES:
        return _SIG_FILE_MODULES[stem]
    return stem.upper() or default


def _crt_candidates(cfg: Any) -> list[LibCandidate]:
    """CRT source matches — the strongest provenance."""
    from rebrew.crt_match import match_all

    try:
        matches = match_all(cfg)
    except Exception as exc:  # best-effort backend
        console.print(f"[yellow]warning:[/yellow] CRT matching skipped: {exc}")
        return []
    out: list[LibCandidate] = []
    for m in matches:
        out.append(
            LibCandidate(
                va=m.va,
                name=m.source.name,
                module=m.source.module.upper(),
                kind="crt",
                confidence=m.confidence,
                source_ref=m.source.file,
            )
        )
    return out


def _flirt_candidates(cfg: Any, default_module: str) -> list[LibCandidate]:
    """FLIRT hits from the project's flirt_sigs (skipped when absent).

    Each signature file is scanned independently so its module attribution
    comes from the file name (``msvcrt_vc6.pat`` → MSVCRT, ``zlib_vc6.pat`` →
    ZLIB); the name-prefix tables (CRT/zlib) refine individual hits.
    """
    sig_dir = cfg.root / "flirt_sigs" if getattr(cfg, "root", None) else None
    if sig_dir is None or not sig_dir.is_dir():
        return []
    sig_files = list(sig_dir.glob("*.sig")) + list(sig_dir.glob("*.pat"))
    if not sig_files:
        return []

    import flirt

    from rebrew.binary_loader import load_binary
    from rebrew.flirt import match_text

    try:
        info = load_binary(cfg.target_binary)
        text_sec = info.sections.get(".text") or info.sections.get("__text")
        if text_sec is None:
            return []
        code_data = info.data[text_sec.file_offset : text_sec.file_offset + text_sec.raw_size]
    except Exception as exc:
        console.print(f"[yellow]warning:[/yellow] FLIRT identification skipped: {exc}")
        return []

    out: list[LibCandidate] = []
    for sig_file in sig_files:
        try:
            if sig_file.suffix == ".sig":
                sigs = flirt.parse_sig(sig_file.read_bytes())
            else:
                sigs = flirt.parse_pat(sig_file.read_text(encoding="utf-8", errors="ignore"))
        except Exception as exc:  # one bad file must not abort the rest
            console.print(f"[yellow]warning:[/yellow] unreadable signature {sig_file.name}: {exc}")
            continue
        if not sigs:
            continue
        file_module = _module_from_sig_file(sig_file.name, default_module)
        try:
            matcher = flirt.compile(sigs)
        except Exception as exc:
            console.print(
                f"[yellow]warning:[/yellow] uncompileable signature {sig_file.name}: {exc}"
            )
            continue
        for m in match_text(matcher, code_data, text_sec.va):
            out.append(
                LibCandidate(
                    va=m["va"],
                    name=m["name"],
                    module=_infer_module(m["name"], file_module),
                    kind="flirt",
                    confidence=0.5,
                )
            )
    return out


def _import_candidates(cfg: Any, default_module: str) -> list[LibCandidate]:
    """IAT import stubs — jmp [IAT] thunks identify the imported API.

    The module comes from the import table's DLL (KERNEL32, DDRAW, ...), not
    a name heuristic — DirectDrawCreate is DirectX, not MSVCRT.  Names not
    found in the import table fall back to the CRT-prefix heuristic.
    """
    from rebrew.imports import find_import_stubs, parse_imports

    try:
        stubs = find_import_stubs(cfg.target_binary)
    except Exception as exc:
        console.print(f"[yellow]warning:[/yellow] import-stub detection skipped: {exc}")
        return []
    # API name -> DLL basename (uppercase, no extension).
    dll_by_name: dict[str, str] = {}
    try:
        for rec in parse_imports(cfg.target_binary):
            name = str(rec.get("name", ""))
            dll = str(rec.get("dll", ""))
            if name and dll:
                dll_by_name[name] = dll.rsplit(".", 1)[0].upper()
    except Exception:  # import parse is best-effort
        dll_by_name = {}

    out: list[LibCandidate] = []
    for va, name in stubs.items():
        module = dll_by_name.get(str(name)) or _infer_module(str(name), default_module)
        out.append(
            LibCandidate(
                va=va,
                name=str(name),
                module=module,
                kind="import",
                confidence=0.3,
            )
        )
    return out


def _existing_vas(cfg: Any) -> set[int]:
    """VAs that already have a FUNCTION/LIBRARY annotation anywhere."""
    from rebrew.crt_match import collect_library_annotations

    try:
        return {ann.va for _path, ann in collect_library_annotations(cfg)}
    except Exception:
        return set()


def collect_candidates(cfg: Any, default_module: str | None = None) -> list[LibCandidate]:
    """Run all three backends and merge by VA (best provenance wins)."""
    if not default_module:
        lib_modules = [m for m in (getattr(cfg, "library_modules", []) or []) if m]
        default_module = (lib_modules[0] if lib_modules else "MSVCRT").upper()

    merged: dict[int, LibCandidate] = {}
    for cand in (
        _crt_candidates(cfg)
        + _flirt_candidates(cfg, default_module)
        + _import_candidates(cfg, default_module)
    ):
        existing = merged.get(cand.va)
        if existing is None or _KIND_RANK[cand.kind] > _KIND_RANK[existing.kind]:
            merged[cand.va] = cand
    return sorted(merged.values(), key=lambda c: c.va)


def _append_entry(header: Path, cand: LibCandidate) -> None:
    """Append one minimal reccmp-compatible LIBRARY entry to *header*."""
    block = f"// LIBRARY: {cand.module} 0x{cand.va:08x}\n// {cand.name}\n\n"
    with header.open("a", encoding="utf-8") as f:
        f.write(block)


def write_candidates(cfg: Any, candidates: list[LibCandidate], existing: set[int]) -> int:
    """Write new ``library_<module>.h`` entries for *candidates*.

    Only VAs not in *existing* are written (idempotent).  High-confidence CRT
    matches also get their SOURCE metadata written.  Returns the count.
    """
    from rebrew.annotation import update_annotation_key

    written = 0
    by_module: dict[str, list[LibCandidate]] = {}
    for cand in candidates:
        if cand.va in existing:
            continue
        by_module.setdefault(cand.module, []).append(cand)

    for module, cands in sorted(by_module.items()):
        header = cfg.reversed_dir / f"library_{module.lower()}.h"
        for cand in cands:
            _append_entry(header, cand)
            if cand.kind == "crt" and cand.confidence >= 0.85 and cand.source_ref:
                try:
                    update_annotation_key(
                        header,
                        cand.va,
                        "SOURCE",
                        cand.source_ref,
                        metadata_dir=cfg.metadata_dir,
                    )
                except Exception as exc:  # SOURCE is best-effort
                    console.print(
                        f"[yellow]warning:[/yellow] SOURCE write failed for 0x{cand.va:08x}: {exc}"
                    )
            written += 1
    return written


def _iter_libs(libs_dir: Path) -> Iterator[Path]:
    """Yield *.lib files in *libs_dir*, case-insensitively (MSVC ships .LIB)."""
    for p in sorted(libs_dir.iterdir()):
        if p.is_file() and p.suffix.lower() == ".lib":
            yield p


def _resolve_lib_dir(cfg: Any, lib_dir: Path | None) -> Path | None:
    """Locate the toolchain's .lib directory (for --build-sigs).

    Order: explicit --lib-dir → ``toolchain/msvc/6.0-win32/source/VC98/Lib`` → first directory
    under ``tools/`` containing ``*.lib`` files.
    """
    if lib_dir is not None:
        return lib_dir if lib_dir.is_dir() else None
    candidates: list[Path] = [cfg.root / "tools" / "msvc-6.0-win32" / "VC98" / "Lib"]
    if getattr(cfg, "root", None):
        for pattern in ("tools/*/Lib", "tools/*/*/Lib"):
            candidates.extend(sorted(cfg.root.glob(pattern)))
    for cand in candidates:
        if cand.is_dir() and list(_iter_libs(cand)):
            return cand
    return None


def build_flirt_sigs(cfg: Any, lib_dir: Path | None = None) -> int:
    """Generate ``flirt_sigs/<lib>_vc6.pat`` from every ``*.lib`` in *lib_dir*.

    Returns the number of .pat files written (0 when no libs are found).
    """
    from rebrew.gen_flirt_pat import generate_pat

    libs_dir = _resolve_lib_dir(cfg, lib_dir)
    if libs_dir is None:
        console.print(
            "[yellow]warning:[/yellow] no .lib directory found (tried toolchain/msvc/6.0-win32/source/"
            "VC98/Lib and tools/*/Lib) — pass --lib-dir"
        )
        return 0
    out_dir = cfg.root / "flirt_sigs"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    for lib in _iter_libs(libs_dir):
        out_path = out_dir / f"{lib.stem.lower()}_vc6.pat"
        try:
            stats = generate_pat(lib, out_path)
        except (ValueError, OSError) as exc:
            # One corrupt/non-COFF .lib (e.g. an import library) must not
            # abort sig generation for the other 200+.
            skipped += 1
            console.print(f"[yellow]warning:[/yellow] skipped {lib.name}: {exc}")
            continue
        written += 1
        console.print(
            f"[green]{out_path.name}[/green]: {stats['signatures']} signatures "
            f"({stats['skipped_weak']} weak skipped)"
        )
    if skipped:
        console.print(f"[dim]{skipped} unparseable .lib file(s) skipped[/dim]")
    return written


@app.callback(invoke_without_command=True)
def main(
    module: str | None = typer.Option(
        None,
        "--module",
        help="Default module for names no backend classified (default: first "
        "configured library_modules, else MSVCRT).",
    ),
    build_sigs: bool = typer.Option(
        False,
        "--build-sigs",
        help="Generate flirt_sigs/*.pat from the toolchain's .lib files first, "
        "then identify with them.",
    ),
    lib_dir: Path | None = typer.Option(
        None,
        "--lib-dir",
        help="Toolchain .lib directory for --build-sigs (default: "
        "toolchain/msvc/6.0-win32/source/VC98/Lib or the first tools/*/Lib found).",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Identify library functions and write library_*.h entries."""

    cfg = require_config(target=target, json_mode=json_output)

    # Generate sigs once (even in dry-run: the .pat files are build artifacts
    # the identification needs; only the library_*.h writes are previewed).
    sigs_written = 0
    if build_sigs:
        sigs_written = build_flirt_sigs(cfg, lib_dir)

    candidates = collect_candidates(cfg, module)
    existing = _existing_vas(cfg)

    fresh = [c for c in candidates if c.va not in existing]
    if dry_run or json_output:
        payload = {
            "sigs_written": sigs_written,
            "identified": len(candidates),
            "already_annotated": len(candidates) - len(fresh),
            "to_write": len(fresh),
            "candidates": [
                {
                    "va": f"0x{c.va:08x}",
                    "name": c.name,
                    "module": c.module,
                    "kind": c.kind,
                    "confidence": round(c.confidence, 2),
                }
                for c in candidates
            ],
        }
        if json_output:
            json_print(payload)
        else:
            console.print(f"[bold]Identified:[/bold] {len(candidates)} library functions")
            console.print(
                f"[dim]{len(candidates) - len(fresh)} already annotated, "
                f"{len(fresh)} to write[/dim]"
            )
            if build_sigs:
                console.print(f"[dim]sigs_written: {payload['sigs_written']}[/dim]")
            for c in fresh:
                console.print(
                    f"  [dim]0x{c.va:08x}[/dim] {c.name} ({c.module}, {c.kind}, "
                    f"conf {c.confidence:.2f})"
                )
            if not dry_run:
                console.print("[yellow]dry-run not set — this would write.[/yellow]")
        return

    written = write_candidates(cfg, candidates, existing)
    console.print(
        f"[green]Wrote {written} library entr{'y' if written == 1 else 'ies'}[/green] "
        f"({len(candidates)} identified, {len(candidates) - written} already annotated)."
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
