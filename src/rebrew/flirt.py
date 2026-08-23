"""Run FLIRT signature matching against functions in the target binary.

Usage: rebrew flirt [sig_dir]
"""

import os
import warnings
from pathlib import Path
from typing import Any

import flirt
import typer
from rich.console import Console

from rebrew.binary_loader import load_binary
from rebrew.cli import TargetOption, error_exit, json_print, parse_va, require_config

console = Console(stderr=True)

_MAX_FUNC_SCAN = 4096
_MIN_MATCH_WINDOW = 32
_FUNC_ALIGNMENT = 16
_MAX_AMBIGUOUS = 3
_MAX_AMBIGUOUS_REPORT = 12  # cap on candidate names kept per ambiguous match


def _flirt_sigs_repo() -> Path:
    """Root of the standalone rebrew-flirt-sigs checkout (standard library sigs).

    Defaults to the sibling checkout (same workspace as this repo), like
    rebrew-toolchains; overridable via REBREW_FLIRT_SIGS_DIR.  Project-specific
    sigs stay in the project's own ``flirt_sigs/`` and are merged on top.
    """
    env = os.environ.get("REBREW_FLIRT_SIGS_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2].parent / "rebrew-flirt-sigs"


def _sig_files(dirs: list[Path]) -> list[Path]:
    """All ``.sig``/``.pat`` files across *dirs*, deduped by name (first wins)."""
    seen: dict[str, Path] = {}
    for d in dirs:
        if not d.is_dir():
            continue
        for suffix in (".sig", ".pat"):
            for p in sorted(d.glob(f"*{suffix}")):
                seen.setdefault(p.name, p)
    return list(seen.values())


def _parse_sig_files(files: list[Path]) -> list[Any]:
    """Parse each FLIRT signature file, warning (not aborting) on bad ones."""
    sigs: list[Any] = []
    for filepath in files:
        try:
            content = filepath.read_bytes()
            if filepath.suffix == ".sig":
                parsed = flirt.parse_sig(content)
            else:
                parsed = flirt.parse_pat(content.decode("utf-8", errors="ignore"))
            sigs.extend(parsed)
            console.print(f"Loaded {len(parsed)} signatures from {filepath.name}")
        except (OSError, ValueError, TypeError) as e:
            warnings.warn(f"Error loading {filepath}: {e}", stacklevel=2)
        except Exception as e:  # noqa: BLE001 — python-flirt can raise
            # struct.error / IndexError / UnicodeDecodeError on malformed
            # signatures; one bad file must not abort the whole scan.
            warnings.warn(f"Error parsing {filepath}: {e}", stacklevel=2)
    return sigs


def load_signatures(sig_dir: str) -> list[Any]:
    """Load all ``.sig`` and ``.pat`` FLIRT signature files from *sig_dir*."""
    console.print(f"Loading signatures from {sig_dir}...")

    sig_path = Path(sig_dir)
    if not sig_path.exists():
        console.print(f"Signature directory {sig_dir} not found.")
        return []

    return _parse_sig_files(sorted(sig_path.glob("*.sig")) + sorted(sig_path.glob("*.pat")))


def load_signatures_merged(project_dir: Path, repo_dir: Path) -> list[Any]:
    """Load signatures from the project dir merged with the rebrew-flirt-sigs repo.

    Project-specific sigs win on name conflicts (deduped by filename);
    missing dirs are skipped.  The repo dir may be overridden via
    ``REBREW_FLIRT_SIGS_DIR`` (resolved by :func:`_flirt_sigs_repo`).
    """
    files = _sig_files([project_dir, repo_dir])
    if not files:
        console.print(
            f"No signature files in {project_dir} or {repo_dir} — "
            "clone the rebrew-flirt-sigs checkout next to this repo "
            "(or set REBREW_FLIRT_SIGS_DIR)."
        )
        return []
    return _parse_sig_files(files)


def find_func_size(code_data: bytes, offset: int) -> int:
    """Estimate function size by scanning for common end patterns."""
    # Look for ret (0xC3), ret imm16 (0xC2), or int3 padding (0xCC)
    max_scan = min(_MAX_FUNC_SCAN, len(code_data) - offset)
    scan_end = offset + max_scan
    for i in range(offset, scan_end):
        b = code_data[i]
        if b == 0xC3:  # ret
            return i - offset + 1
        # ret imm16 (C2 xx xx): 3-byte instruction, must fit within scan window
        if b == 0xC2 and i + 2 < scan_end:
            return i - offset + 3
    return max_scan


def iter_match_offsets(code_size: int, *, stride: int = 16, min_window: int = 32) -> range:
    """Return a range of byte offsets to probe for FLIRT matches."""
    if code_size < min_window:
        return range(0)
    last_start = code_size - min_window
    return range(0, last_start + 1, stride)


def match_text(
    matcher: Any,
    code_data: bytes,
    base_va: int,
    *,
    stride: int = _FUNC_ALIGNMENT,
    max_ambiguous: int = _MAX_AMBIGUOUS,
) -> list[dict[str, Any]]:
    """Scan *code_data* with a compiled FLIRT *matcher*.

    Returns one dict per unambiguous match: ``{"va", "size", "name"}`` where
    *va* is ``base_va + offset``.  Broad signatures (more than
    *max_ambiguous* candidate names at one offset) are skipped so library
    identification never guesses.  Shared by ``rebrew flirt``, ``rebrew
    analyze``, and ``rebrew identify-library``.
    """
    matches: list[dict[str, Any]] = []
    for offset in iter_match_offsets(len(code_data), stride=stride, min_window=_MIN_MATCH_WINDOW):
        hits = matcher.match(code_data[offset : offset + 1024])
        if not hits:
            continue
        names: list[str] = []
        for m in hits:
            for n in m.names:
                label = n[0] if isinstance(n, tuple) else str(n)
                if label and label not in names:
                    names.append(label)
        if not names:
            continue
        if len(names) > max_ambiguous:
            continue  # ambiguous — never guess
        matches.append(
            {"va": base_va + offset, "size": find_func_size(code_data, offset), "name": names[0]}
        )
    return matches


app = typer.Typer(
    help="FLIRT signature scanner for binaries.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew flirt · · · · · · · · · · Scan with default .sig files\n\n"
        "  rebrew flirt sigs/ · · · · · · · Use custom signature directory\n\n"
        "  rebrew flirt --json · · · · · · · Output matches as JSON\n\n"
        "  rebrew flirt --min-size 32 · · · · Only report functions ≥32 bytes\n\n"
        "[bold]How it works:[/bold]\n\n"
        "  Scans the target binary using FLIRT (Fast Library Identification and "
        "Recognition Technology) signatures to identify known library functions "
        "(MSVCRT, DirectX, Zlib, etc.).\n\n"
        "[dim]Signatures load from the project's flirt_sigs/ merged with the "
        "rebrew-flirt-sigs checkout (REBREW_FLIRT_SIGS_DIR overrides); or pass "
        "a SIG_DIR argument. Reads target binary path from rebrew-project.toml.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    sig_dir: Path | None = typer.Argument(None, help="Directory containing .sig/.pat files"),
    exe: Path | None = typer.Option(None, "--exe", help="Target PE file (default: from config)"),
    min_size: int = typer.Option(16, "--min-size", help="Minimum function size in bytes to report"),
    va_filter: str | None = typer.Option(
        None, "--va", help="Check a single function VA (hex) instead of the whole .text"
    ),
    show_ambiguous: bool = typer.Option(
        False,
        "--show-ambiguous",
        help=(f"Report ambiguous matches (offsets with >{_MAX_AMBIGUOUS} candidate names) as well"),
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """FLIRT signature scanner for binaries."""
    cfg = require_config(target=target, json_mode=json_output)

    final_exe = exe or cfg.target_binary

    # 1. Load FLIRT signatures: explicit dir, else project flirt_sigs/ merged
    # with the rebrew-flirt-sigs checkout (standard library sigs).
    if sig_dir is not None:
        sigs = load_signatures(str(sig_dir))
        sig_sources = [str(sig_dir)]
    else:
        project_dir = cfg.root / "flirt_sigs"
        repo_dir = _flirt_sigs_repo()
        sigs = load_signatures_merged(project_dir, repo_dir)
        sig_sources = [str(project_dir), str(repo_dir)]
    if not sigs:
        error_exit("No signatures loaded", json_mode=json_output)

    console.print("Compiling FLIRT matching engine...")
    matcher = flirt.compile(sigs)

    # 2. Extract function bytes from binary
    console.print(f"Analyzing {final_exe}...")
    info = load_binary(final_exe)

    # Find the text section (PE: .text, Mach-O: __text)
    text_name = ".text" if ".text" in info.sections else "__text"
    if text_name not in info.sections:
        error_exit("Could not find .text section", json_mode=json_output)

    text_sec = info.sections[text_name]
    code_data = info.data[text_sec.file_offset : text_sec.file_offset + text_sec.raw_size]
    base_va = text_sec.va

    sig_count = len(sigs)
    console.print(
        f"Searching for signature matches in {len(code_data)} bytes "
        f"(min function size: {min_size}B)..."
    )

    found = 0
    skipped = 0
    matches_list: list[dict[str, Any]] = []
    ambiguous_list: list[dict[str, Any]] = []
    stride = _FUNC_ALIGNMENT
    max_ambiguous = _MAX_AMBIGUOUS

    # Guard: FLIRT signatures need at least _MIN_MATCH_WINDOW bytes to match.
    # Note: this is a warning only — the shared JSON block below still emits
    # the full schema (and the --va single-function check still runs).
    if len(code_data) < _MIN_MATCH_WINDOW:
        console.print(
            f"Warning: .text section too small ({len(code_data)} bytes) for FLIRT matching"
        )

    def _check_offset(offset: int, *, force: bool = False) -> None:
        """Match one .text offset against the signature index (helper for both modes).

        *force* bypasses the size gate — the explicit ``--va`` probe is about
        one function the user named, so a short function must not silently
        report "no match" because the scan heuristic suppressed it.
        """
        nonlocal found, skipped
        hits = matcher.match(code_data[offset : offset + 1024])
        if not hits:
            return
        names: list[str] = []
        for m in hits:
            for n in m.names:
                # n is (name, type, offset) tuple
                label = n[0] if isinstance(n, tuple) else str(n)
                if label and label not in names:
                    names.append(label)
        if not names:
            return
        func_size = find_func_size(code_data, offset)
        if not force and func_size < min_size:
            return
        va = base_va + offset
        if len(names) > max_ambiguous:
            # Broad signatures (e.g. crc_len=0 patterns) can match many
            # candidates at once.  Skipped by default; --show-ambiguous keeps
            # them so the identification candidates aren't lost entirely.
            skipped += 1
            if show_ambiguous:
                ambiguous_list.append(
                    {
                        "va": f"0x{va:08x}",
                        "size": func_size,
                        "names": names[:_MAX_AMBIGUOUS_REPORT],
                        "more": len(names) > _MAX_AMBIGUOUS_REPORT,
                    }
                )
                if not json_output:
                    shown = ", ".join(names[:_MAX_AMBIGUOUS_REPORT])
                    if len(names) > _MAX_AMBIGUOUS_REPORT:
                        shown += ", ..."
                    console.print(f"[dim]~ 0x{va:08x} ({func_size:4d}B): ambiguous: {shown}[/dim]")
            return
        if json_output:
            matches_list.append({"va": f"0x{va:08x}", "size": func_size, "names": names})
        else:
            console.print(f"[+] 0x{va:08x} ({func_size:4d}B): {', '.join(names)}")
        found += 1

    if va_filter:
        # Single-function mode: check just this VA (used by `rebrew todo`
        # identify-library items).
        va_int = parse_va(va_filter, json_mode=json_output)
        offset = va_int - base_va
        if not (0 <= offset < len(code_data)):
            error_exit(
                f"VA 0x{va_int:08x} outside .text (0x{base_va:x}..0x{base_va + len(code_data):x})",
                json_mode=json_output,
            )
        _check_offset(offset, force=True)
    else:
        for offset in iter_match_offsets(
            len(code_data), stride=stride, min_window=_MIN_MATCH_WINDOW
        ):
            _check_offset(offset)

    if json_output:
        output: dict[str, Any] = {
            "binary": str(final_exe),
            "sig_dirs": sig_sources,
            "signature_count": sig_count,
            "text_size": len(code_data),
            "min_size": min_size,
            "match_count": found,
            "skipped_ambiguous": skipped,
            "matches": matches_list,
            "ambiguous_matches": ambiguous_list,
        }
        if len(code_data) < _MIN_MATCH_WINDOW:
            output["warning"] = f".text section too small ({len(code_data)} bytes)"
        json_print(output)
    else:
        console.print(f"\nTotal matches found: {found}")
        if skipped:
            console.print(f"Skipped {skipped} ambiguous matches (>{max_ambiguous} candidate names)")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
