"""Run FLIRT signature matching against functions in the target binary.
Usage: rebrew flirt [sig_dir]
"""

import sys
from collections.abc import Callable
from importlib import import_module
from pathlib import Path

import typer

from rebrew.binary_loader import load_binary
from rebrew.cli import TargetOption, error_exit, get_config, json_print

try:
    flirt: object | None = import_module("flirt")
except ImportError:
    flirt = None


def load_signatures(sig_dir: str, json_output: bool = False) -> list[object]:
    """Load all ``.sig`` and ``.pat`` FLIRT signature files from *sig_dir*."""
    if flirt is None:
        return []

    _print = _make_progress_printer(json_output)
    _print(f"Loading signatures from {sig_dir}...")
    sigs: list[object] = []

    sig_path = Path(sig_dir)
    if not sig_path.exists():
        _print(f"Signature directory {sig_dir} not found.")
        return []

    sig_files = sorted(sig_path.glob("*.sig")) + sorted(sig_path.glob("*.pat"))
    for filepath in sig_files:
        try:
            content = filepath.read_bytes()
            if filepath.suffix == ".sig":
                parsed = flirt.parse_sig(content)
            else:
                parsed = flirt.parse_pat(content.decode("utf-8", errors="ignore"))
            sigs.extend(parsed)
            _print(f"Loaded {len(parsed)} signatures from {filepath.name}")
        except (OSError, ValueError, TypeError) as e:
            print(f"Error loading {filepath}: {e}", file=sys.stderr)

    return sigs


def find_func_size(code_data: bytes, offset: int) -> int:
    """Estimate function size by scanning for common end patterns."""
    # Look for ret (0xC3), ret imm16 (0xC2), or int3 padding (0xCC)
    max_scan = min(4096, len(code_data) - offset)
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


def _make_progress_printer(json_output: bool) -> Callable[..., None]:
    """Return a print function that goes to stderr when json_output is True."""
    if json_output:

        def _print(*args: object, **kwargs: object) -> None:
            kwargs["file"] = sys.stderr
            print(*args, **kwargs)

        return _print
    return print


app = typer.Typer(
    help="FLIRT signature scanner for binaries.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew flirt                                  Scan with default .sig files

rebrew flirt sigs/                            Use custom signature directory

rebrew flirt --json                           Output matches as JSON

rebrew flirt --min-size 32                    Only report functions ≥32 bytes

[bold]How it works:[/bold]

Scans the target binary using FLIRT (Fast Library Identification and
Recognition Technology) signatures to identify known library functions
(MSVCRT, DirectX, Zlib, etc.).

[dim]Requires .sig/.pat signature files in the project or passed via --sig-dir.
Reads target binary path from rebrew-project.toml.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    sig_dir: Path | None = typer.Argument(None, help="Directory containing .sig/.pat files"),
    exe: Path | None = typer.Option(None, help="Target PE file (default: from config)"),
    min_size: int = typer.Option(16, help="Minimum function size in bytes to report (default: 16)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """FLIRT signature scanner for binaries"""
    if flirt is None:
        error_exit("flirt module not found. Run 'uv sync' to install dependencies.")
    cfg = get_config(target=target)
    _print = _make_progress_printer(json_output)

    final_sig_dir = sig_dir or (cfg.root / "flirt_sigs")
    final_exe = exe or cfg.target_binary

    # 1. Load FLIRT signatures
    sigs = load_signatures(str(final_sig_dir), json_output=json_output)
    if not sigs:
        error_exit("No signatures loaded", json_mode=json_output)

    _print("Compiling FLIRT matching engine...")
    matcher = flirt.compile(sigs)

    # 2. Extract function bytes from binary
    _print(f"Analyzing {final_exe}...")
    info = load_binary(final_exe)

    # Find the text section (PE: .text, Mach-O: __text)
    text_name = ".text" if ".text" in info.sections else "__text"
    if text_name not in info.sections:
        error_exit("Could not find .text section", json_mode=json_output)

    text_sec = info.sections[text_name]
    code_data = info.data[text_sec.file_offset : text_sec.file_offset + text_sec.raw_size]
    base_va = text_sec.va

    sig_count = len(sigs)
    _print(
        f"Searching for signature matches in {len(code_data)} bytes "
        f"(min function size: {min_size}B)..."
    )

    found = 0
    skipped = 0
    matches_list: list[dict[str, object]] = []
    stride = 16  # standard function alignment
    max_ambiguous = 3  # if more unique names match, it's noise

    # Guard: FLIRT signatures need at least 32 bytes to match against
    if len(code_data) < 32:
        _print(f"Warning: .text section too small ({len(code_data)} bytes) for FLIRT matching")
        if json_output:
            json_print(
                {
                    "binary": str(final_exe),
                    "signatures_loaded": sig_count,
                    "matches": [],
                    "found": 0,
                    "skipped": 0,
                    "warning": f".text section too small ({len(code_data)} bytes)",
                }
            )
        return

    for offset in iter_match_offsets(len(code_data), stride=stride, min_window=32):
        # Estimate the function size at this offset
        func_size = find_func_size(code_data, offset)
        if func_size < min_size:
            continue

        matches = matcher.match(code_data[offset : offset + 1024])
        if matches:
            va = base_va + offset
            names: list[str] = []
            for m in matches:
                for n in m.names:
                    # n is (name, type, offset) tuple
                    label = n[0] if isinstance(n, tuple) else str(n)
                    if label and label not in names:
                        names.append(label)
            if not names:
                continue
            if len(names) > max_ambiguous:
                skipped += 1
                continue
            if json_output:
                matches_list.append(
                    {
                        "va": f"0x{va:08x}",
                        "size": func_size,
                        "names": names,
                    }
                )
            else:
                print(f"[+] 0x{va:08x} ({func_size:4d}B): {', '.join(names)}")
            found += 1

    if json_output:
        output: dict[str, object] = {
            "binary": str(final_exe),
            "sig_dir": str(final_sig_dir),
            "signature_count": sig_count,
            "text_size": len(code_data),
            "min_size": min_size,
            "match_count": found,
            "skipped_ambiguous": skipped,
            "matches": matches_list,
        }
        json_print(output)
    else:
        print(f"\nTotal matches found: {found}")
        if skipped:
            print(f"Skipped {skipped} ambiguous matches (>{max_ambiguous} candidate names)")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
