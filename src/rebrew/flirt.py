"""Run FLIRT signature matching against functions in the target binary.

Usage: rebrew flirt [sig_dir]
"""

import json
import logging
import os
import warnings
from pathlib import Path
from typing import Any

try:
    import flirt
except ImportError:  # optional dependency
    flirt = None

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
    """All ``.sig``/``.pat`` files under *dirs*, deduped by stem (first wins).

    Recursive: rebrew-flirt-sigs groups signatures by compiler family
    (``sigs/<family>/<toolchain>/``) and mirrors public collections under
    ``sigs/harvested/``.  A flat project ``flirt_sigs/`` keeps working.

    Deduping by stem (not filename) means a compiled ``.sig`` shadows the
    ``.pat`` it was built from wherever both ship: they carry the same
    patterns, but python-flirt parses the binary form ~10,000x faster.  An
    earlier directory still wins outright, so a project's own sigs override
    the shared checkout.
    """
    seen: dict[str, Path] = {}
    for d in dirs:
        if not d.is_dir():
            continue
        for suffix in (".sig", ".pat"):
            for p in sorted(d.rglob(f"*{suffix}")):
                seen.setdefault(p.stem, p)
    return list(seen.values())


def _init_project_sigs(cfg: Any, json_output: bool, matched_only: bool = False) -> None:
    """Copy the shared sig checkout into the project's ``flirt_sigs/``.

    Explicit, versioned per project: later upstream additions don't silently
    change a project's matches.  Existing project files win (never
    overwritten) — delete one to re-sync it.

    With *matched_only*, copy just the CRT family matching the target's
    detected linkage (static→``libcmt*``, dynamic→``msvcrt*``/``crtdll*``;
    unknown linkage copies both) plus the WinAPI import sigs — typically a
    third of the checkout instead of all 260+ files.
    """
    from rebrew.cli import error_exit, json_print

    repo = _flirt_sigs_repo()
    if not repo.is_dir():
        error_exit(
            f"signature source not found: {repo} — clone rebrew-flirt-sigs "
            "next to this repo or set REBREW_FLIRT_SIGS_DIR",
            json_mode=json_output,
        )
    wanted: set[str] | None = None
    linkage = ""
    if matched_only:
        linkage = _detect_crt_linkage(cfg)
        wanted = _matched_sig_names(linkage)
    dest = Path(cfg.root) / "flirt_sigs"
    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    for src in _sig_files([repo]):
        if wanted is not None and src.name not in wanted:
            continue
        target = dest / src.name
        if target.exists():
            continue
        target.write_bytes(src.read_bytes())
        copied += 1
    total = len(_sig_files([dest]))
    if json_output:
        json_print({"copied": copied, "total": total, "dir": str(dest), "linkage": linkage})
        return
    console.print(f"[green]flirt_sigs/: {copied} copied, {total} total[/green]")


def _detect_crt_linkage(cfg: Any) -> str:
    """``static`` / ``dynamic`` / ``""`` for the target binary."""
    try:
        from rebrew.toolchain_detect import detect_toolchain

        info = detect_toolchain(Path(cfg.target_binary))
        return str(info.crt_linkage or "")
    except Exception:
        # Unknown linkage keeps every CRT-ish sig (see ``_matched_sig_names``);
        # log so a real detection failure is not mistaken for "no CRT".
        logging.getLogger(__name__).debug(
            "CRT linkage detection failed for %s",
            getattr(cfg, "target_binary", "?"),
            exc_info=True,
        )
        return ""


#: CRT sig stems by linkage (``*_vc6.pat`` suffix stripped for matching).
_CRT_STATIC_STEMS = ("libcmt", "libcmtd")
_CRT_DYNAMIC_STEMS = ("msvcrt", "msvcrtd", "msvcirt", "msvcirtd", "crtdll")


def _matched_sig_names(linkage: str) -> set[str]:
    """Sig filenames worth copying for *linkage* (best-effort heuristics).

    Unknown linkage keeps everything CRT-ish plus WinAPI; known linkage
    keeps its own CRT family plus WinAPI and drops the other family (a
    static binary never matches msvcrt imports and vice versa).
    """
    names: set[str] = set()
    repo = _flirt_sigs_repo()
    if not repo.is_dir():
        return names
    for src in _sig_files([repo]):
        stem = src.name.lower()
        is_crt = stem.startswith(_CRT_STATIC_STEMS + _CRT_DYNAMIC_STEMS)
        if (
            not is_crt
            or not linkage
            or (linkage == "static" and stem.startswith(_CRT_STATIC_STEMS))
            or (linkage == "dynamic" and stem.startswith(_CRT_DYNAMIC_STEMS))
        ):
            names.add(src.name)  # WinAPI + misc always; CRT iff linkage matches
    return names


def _parse_sig_files(files: list[Path]) -> list[Any]:
    """Parse each FLIRT signature file, warning (not aborting) on bad ones."""
    if flirt is None:
        warnings.warn("python-flirt not installed — skipping signature scan", stacklevel=2)
        return []
    sigs: list[Any] = []
    for filepath in files:
        try:
            content = filepath.read_bytes()
            if filepath.suffix.lower() == ".sig":
                parsed = flirt.parse_sig(content)
            else:
                parsed = flirt.parse_pat(content.decode("utf-8", errors="ignore"))
            sigs.extend(parsed)
            console.print(f"Loaded {len(parsed)} signatures from {filepath.name}")
        except (OSError, ValueError, TypeError) as e:
            warnings.warn(f"Error loading {filepath}: {e}", stacklevel=2)
        except Exception as e:  # python-flirt can raise
            # struct.error / IndexError / UnicodeDecodeError on malformed
            # signatures; one bad file must not abort the whole scan.
            warnings.warn(f"Error parsing {filepath}: {e}", stacklevel=2)
    return sigs


def load_signatures(sig_dir: str) -> list[Any]:
    """Load all ``.sig`` and ``.pat`` FLIRT signature files from *sig_dir*."""
    console.print(f"Loading signatures from {sig_dir}...")

    sig_path = Path(sig_dir)
    if not sig_path.is_dir():
        console.print(f"Signature directory {sig_dir} not found or not a directory.")
        return []

    return _parse_sig_files(_sig_files([sig_path]))


#: BinaryInfo.arch -> the signature index's architecture vocabulary.
_ARCH_FAMILIES: dict[str, str] = {
    "x86_16": "x86",
    "x86_32": "x86",
    "x86_64": "x64",
    "arm32": "arm",
    "arm64": "arm64",
    "mips32": "mips",
    "mips64": "mips",
    "ppc32": "ppc",
    "ppc64": "ppc",
}


def _arch_index(dirs: list[Path]) -> dict[str, str]:
    """``name -> arch`` from a ``sigs/index.json`` shipped with the signatures.

    rebrew-flirt-sigs publishes the architecture of every file it could
    classify (``tools/index_sigs.py``); files missing from the index — or
    marked with an empty arch — are unknown and always load.  A checkout
    without an index simply does not filter.
    """
    index: dict[str, str] = {}
    for d in dirs:
        for candidate in (d / "sigs" / "index.json", d / "index.json"):
            if not candidate.is_file():
                continue
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for name, meta in data.get("files", {}).items():
                index.setdefault(name, str(meta.get("arch", "") if isinstance(meta, dict) else ""))
    return index


def load_signatures_for(dirs: list[Path], arch: str = "") -> list[Any]:
    """Load the signatures worth trying for *arch* from *dirs*.

    The whole library is ~12 M patterns and python-flirt builds one matcher
    for everything loaded, which does not fit in memory.  When the signature
    checkout ships an architecture index, files known to belong to another
    architecture are skipped; unknown ones are kept so nothing relevant is
    dropped silently.
    """
    files = _sig_files(dirs)
    if arch and files:
        index = _arch_index(dirs)
        if index:
            before = len(files)
            files = [f for f in files if index.get(f.name, "") in ("", arch)]
            if len(files) != before:
                console.print(
                    f"Architecture {arch}: skipped {before - len(files)} "
                    f"signature file(s) that cannot match"
                )
    if not files:
        console.print(
            f"No signature files in {', '.join(str(d) for d in dirs)} — "
            "clone the rebrew-flirt-sigs checkout next to this repo "
            "(or set REBREW_FLIRT_SIGS_DIR)."
        )
        return []
    return _parse_sig_files(files)


def _capstone_for_arch(arch: str, endian: str = "") -> tuple[int, int]:
    """Capstone ``(cs_arch, mode)`` for a rebrew arch string.

    ``x86_16`` is decoded as 16-bit — the 32-bit default mis-sizes every Win16
    or DOS function.  MIPS follows the file's own endianness (PSP/PS1 are
    little-endian, the N64/PS2 console targets are big-endian); PPC and SH are
    big-endian ISAs.  *endian* is ``"little"``/``"big"``/``""`` (unknown).
    """
    import capstone

    little = endian == "little"
    mips_endian = capstone.CS_MODE_LITTLE_ENDIAN if little else capstone.CS_MODE_BIG_ENDIAN
    table: dict[str, tuple[int, int]] = {
        "x86_16": (capstone.CS_ARCH_X86, capstone.CS_MODE_16),
        "x86_32": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm32": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        "mips32": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | mips_endian),
        "mips64": (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS64 | mips_endian),
        "ppc32": (capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN),
        "ppc64": (capstone.CS_ARCH_PPC, capstone.CS_MODE_64 | capstone.CS_MODE_BIG_ENDIAN),
        "sh2": (capstone.CS_ARCH_SH, capstone.CS_MODE_SH2 | capstone.CS_MODE_BIG_ENDIAN),
    }
    return table.get(arch, (capstone.CS_ARCH_X86, capstone.CS_MODE_32))


#: Probe stride per arch: RISC functions start on an instruction boundary
#: (4 bytes; SH2 instructions are 2), so a 16-byte stride would miss most of
#: them.  x86 keeps the historical 16.
_ARCH_STRIDE: dict[str, int] = {
    "mips32": 4,
    "mips64": 4,
    "arm32": 4,
    "arm64": 4,
    "ppc32": 4,
    "ppc64": 4,
    "sh2": 2,
}


def arch_stride(arch: str) -> int:
    """Probe stride for *arch* (``_FUNC_ALIGNMENT`` when unknown)."""
    return _ARCH_STRIDE.get(arch, _FUNC_ALIGNMENT)


def find_func_size(code_data: bytes, offset: int, arch: str = "x86_32", endian: str = "") -> int:
    """Estimate function size by disassembling to the arch's terminator.

    Capstone decodes from *offset* so a ``0xC3``/``0xC2`` byte that is an
    opcode operand or ModRM (not a real ``ret``) never ends the function
    early; ``int3`` padding and unknown bytes end the scan without
    contributing.  RISC terminators are architecture-specific (``jr $ra`` with
    its delay slot, ``bx lr``, ``blr``, ``rts``).  Falls back to the old byte
    window when capstone is unavailable.

    *arch* is a rebrew arch string (``x86_32``, ``mips32``, ``arm32``, …), not
    the signature family — mis-decoding MIPS as x86 silently returns the whole
    4096-byte scan window for every function.
    """
    if offset < 0:
        offset = 0
    max_scan = min(_MAX_FUNC_SCAN, max(0, len(code_data) - offset))
    if max_scan <= 0:
        return 0
    scan_end = offset + max_scan
    try:
        import capstone

        cs_arch, mode = _capstone_for_arch(arch, endian)
        md: Any = capstone.Cs(cs_arch, mode)
        # skipdata=True makes an undecodable byte emit a `.byte` pseudo-insn
        # (the default skipdata_mnem).  With skipdata=False capstone simply
        # STOPS at that byte, so the loop ended without a terminator and the
        # function was reported as the full 4096-byte window.
        md.skipdata = True
    except Exception as exc:
        logging.getLogger(__name__).debug("capstone skipdata setup failed: %s", exc)
        md = None
    if md is not None:
        for insn in md.disasm(code_data[offset:scan_end], offset):
            mnemonic = str(insn.mnemonic)
            operands = str(insn.op_str)
            done = int(insn.address) - offset + int(insn.size)
            if arch.startswith("mips"):
                # Return jumps carry a delay slot that belongs to the function.
                if mnemonic == "jr" and "$ra" in operands:
                    return min(done + 4, max_scan)
                if mnemonic in ("j", "jr"):
                    return min(done + 4, max_scan)
            elif arch == "arm32":
                if mnemonic == "pop" and "pc" in operands:
                    return done
                if mnemonic == "bx" and "lr" in operands:
                    return done
                if mnemonic == "b":
                    return done
            elif arch == "arm64":
                if mnemonic == "ret":
                    return done
            elif arch.startswith("ppc"):
                if mnemonic in ("blr", "bctr"):
                    return done
            elif arch == "sh2":
                if mnemonic == "rts":
                    return min(done + 2, max_scan)
            else:  # x86
                if mnemonic.startswith("ret"):
                    return done
                if mnemonic in ("int3", "hlt", "ud2"):
                    return int(insn.address) - offset
                if mnemonic == ".byte":
                    return int(insn.address) - offset
        return max_scan
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
    stride: int | None = None,
    arch: str = "x86_32",
    endian: str = "",
    max_ambiguous: int = _MAX_AMBIGUOUS,
) -> list[dict[str, Any]]:
    """Scan *code_data* with a compiled FLIRT *matcher*.

    Returns one dict per unambiguous match: ``{"va", "size", "name"}`` where
    *va* is ``base_va + offset``.  Broad signatures (more than
    *max_ambiguous* candidate names at one offset) are skipped so library
    identification never guesses.  Shared by ``rebrew flirt``, ``rebrew
    analyze``, and ``rebrew identify-library``.

    *stride* defaults to the probe stride for *arch* (4 bytes for RISC, 16 for
    x86); function sizes are decoded with the same architecture and *endian*
    (``"little"``/``"big"``/``""``) — MIPS ships in both byte orders.
    """
    if stride is None:
        stride = arch_stride(arch)
    matches: list[dict[str, Any]] = []
    seen_vas: set[int] = set()
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
        va = base_va + offset
        if va in seen_vas:
            continue  # overlapping stride windows can report the same VA
        seen_vas.add(va)
        matches.append(
            {
                "va": va,
                "size": find_func_size(code_data, offset, arch, endian),
                "name": names[0],
            }
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
    binary: Path | None = typer.Option(
        None, "--binary", help="Target PE file (default: from config)"
    ),
    min_size: int = typer.Option(16, "--min-size", help="Minimum function size in bytes to report"),
    va_filter: str | None = typer.Option(
        None, "--va", help="Check a single function VA (hex) instead of the whole .text"
    ),
    show_ambiguous: bool = typer.Option(
        False,
        "--show-ambiguous",
        help=(f"Report ambiguous matches (offsets with >{_MAX_AMBIGUOUS} candidate names) as well"),
    ),
    init: bool = typer.Option(
        False,
        "--init",
        help="Copy the rebrew-flirt-sigs checkout into the project's flirt_sigs/ and exit",
    ),
    init_matched: bool = typer.Option(
        False,
        "--init-matched",
        help="Copy only the sigs matching the target's detected CRT linkage "
        "(static→libcmt*, dynamic→msvcrt*/crtdll*) plus WinAPI imports, and exit",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """FLIRT signature scanner for binaries."""
    cfg = require_config(target=target, json_mode=json_output)

    if init:
        _init_project_sigs(cfg, json_output)
        return
    if init_matched:
        _init_project_sigs(cfg, json_output, matched_only=True)
        return

    final_exe = binary or cfg.target_binary

    if flirt is None:
        error_exit("python-flirt is not installed", json_mode=json_output)

    # 1. Identify the target first: its architecture decides which signatures
    # are worth loading (the full library does not fit in one matcher).
    console.print(f"Analyzing {final_exe}...")
    info = load_binary(final_exe)
    # Two arch strings, deliberately: the *family* ("mips") selects which
    # signatures to load, while capstone and the probe stride need the native
    # arch ("mips32") and the file's byte order.
    native_arch = getattr(info, "arch", "") or ""
    native_endian = getattr(info, "endian", "") or ""
    arch = _ARCH_FAMILIES.get(native_arch, "")

    # 2. Load FLIRT signatures: an explicit dir, else the project flirt_sigs/
    # merged with the rebrew-flirt-sigs checkout (standard library sigs).
    if sig_dir is not None:
        sigs = load_signatures_for([Path(sig_dir)], arch)
        sig_sources = [str(sig_dir)]
    else:
        project_dir = cfg.root / "flirt_sigs"
        repo_dir = _flirt_sigs_repo()
        if os.environ.get("REBREW_FLIRT_SIGS_DIR") and not repo_dir.is_dir():
            error_exit(
                f"REBREW_FLIRT_SIGS_DIR={repo_dir} is not a directory",
                json_mode=json_output,
            )
        sigs = load_signatures_for([project_dir, repo_dir], arch)
        sig_sources = [str(project_dir), str(repo_dir)]
    if not sigs:
        error_exit("No signatures loaded", json_mode=json_output)

    console.print("Compiling FLIRT matching engine...")
    matcher = flirt.compile(sigs)

    # 3. Extract function bytes from the binary

    # Find the code section: PE/ELF/Mach-O name it .text/__text, but a 16-bit
    # NE or MZ image has only numbered segments, and the largest one holds the
    # code in practice (SEG1 of a NE executable; the MZ loader emits a single
    # pseudo code section).
    # Every executable section, not only `.text`.  Linkers with
    # -ffunction-sections put the code in `.text.<name>` and leave `.text`
    # itself nearly empty: U-Boot's own `.text` is 376 bytes out of 489 KB of
    # code, so a `.text`-only scan finds 2 of its functions instead of 712.
    # `is_code` is set by the ELF loader; formats that do not set it fall back
    # to the single-section heuristic below.
    regions: list[tuple[int, bytes, str]] = []
    for sec_name, sec in info.sections.items():
        if not getattr(sec, "is_code", False):
            continue
        end = min(sec.file_offset + sec.raw_size, len(info.data))
        if end > sec.file_offset:
            regions.append((sec.va, info.data[sec.file_offset : end], sec_name))
    regions.sort(key=lambda region: region[0])

    if not regions:
        text_name = ".text" if ".text" in info.sections else "__text"
        if text_name not in info.sections:
            if getattr(info, "arch", "") == "x86_16" and info.sections:
                text_name = max(info.sections, key=lambda n: info.sections[n].raw_size)
                console.print(f"16-bit image: scanning largest segment {text_name}")
            else:
                error_exit("Could not find .text section", json_mode=json_output)
        text_sec = info.sections[text_name]
        end = min(text_sec.file_offset + text_sec.raw_size, len(info.data))
        regions = [(text_sec.va, info.data[text_sec.file_offset : end], text_name)]

    total_code = sum(len(data) for _va, data, _name in regions)
    sig_count = len(sigs)
    if len(regions) == 1:
        console.print(
            f"Searching for signature matches in {total_code} bytes "
            f"(min function size: {min_size}B)..."
        )
    else:
        console.print(
            f"Searching for signature matches in {total_code} bytes across "
            f"{len(regions)} executable sections (min function size: {min_size}B)..."
        )

    found = 0
    skipped = 0
    matches_list: list[dict[str, Any]] = []
    ambiguous_list: list[dict[str, Any]] = []
    stride = arch_stride(native_arch or arch)
    max_ambiguous = _MAX_AMBIGUOUS

    # Guard: FLIRT signatures need at least _MIN_MATCH_WINDOW bytes to match.
    # Note: this is a warning only — the shared JSON block below still emits
    # the full schema (and the --va single-function check still runs).
    if total_code < _MIN_MATCH_WINDOW:
        console.print(
            f"[yellow]warning:[/yellow] code sections too small ({total_code} bytes) "
            "for FLIRT matching"
        )

    def _check_offset(base_va: int, code_data: bytes, offset: int, *, force: bool = False) -> None:
        """Match one code-section offset against the signature index.

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
        va = base_va + offset
        if len(names) > max_ambiguous:
            # Broad signatures (e.g. crc_len=0 patterns) can match many
            # candidates at once.  Skipped by default; --show-ambiguous keeps
            # them so the identification candidates aren't lost entirely.
            # Ambiguity is a property of the signature, not the function
            # size, so the size gate below does not apply here.
            skipped += 1
            if show_ambiguous:
                func_size = find_func_size(code_data, offset, native_arch, native_endian)
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
        func_size = find_func_size(code_data, offset, native_arch, native_endian)
        if not force and func_size < min_size:
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
        for base_va, code_data, _name in regions:
            offset = va_int - base_va
            if 0 <= offset < len(code_data):
                _check_offset(base_va, code_data, offset, force=True)
                break
        else:
            spans = ", ".join(
                f"0x{base_va:x}..0x{base_va + len(code_data):x}"
                for base_va, code_data, _name in regions
            )
            error_exit(
                f"VA 0x{va_int:08x} is in no code section ({spans})",
                json_mode=json_output,
            )
    else:
        for base_va, code_data, _name in regions:
            for offset in iter_match_offsets(
                len(code_data), stride=stride, min_window=_MIN_MATCH_WINDOW
            ):
                _check_offset(base_va, code_data, offset)

    if json_output:
        output: dict[str, Any] = {
            "binary": str(final_exe),
            "sig_dirs": sig_sources,
            "signature_count": sig_count,
            "text_size": total_code,
            "min_size": min_size,
            "match_count": found,
            "skipped_ambiguous": skipped,
            "matches": matches_list,
            "ambiguous_matches": ambiguous_list,
        }
        if total_code < _MIN_MATCH_WINDOW:
            output["warning"] = f"code sections too small ({total_code} bytes)"
        json_print(output)
    else:
        console.print(f"\nTotal matches found: {found}")
        if skipped:
            console.print(f"Skipped {skipped} ambiguous matches (>{max_ambiguous} candidate names)")


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
