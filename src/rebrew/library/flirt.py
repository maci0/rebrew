"""Run FLIRT signature matching against functions in the target binary.

Usage: rebrew library scan-signatures [sig_dir]
"""

from pathlib import Path
lazy import json
lazy import logging
lazy import os
lazy import warnings
lazy from collections.abc import Mapping
lazy from typing import Any

try:
    import flirt
except ImportError:  # optional dependency
    flirt = None

import typer

from rebrew.cli import TargetOption, console, error_exit, json_print, parse_va, require_config
from rebrew.errors import RebrewError
lazy from rebrew.config import REBREW_FLIRT_SIGS_DIR_ENV, ConfigError, env_dir_path
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.utils import SOURCE_CHECKOUT, atomic_write_bytes, read_json_text

_MAX_FUNC_SCAN = 4096
_MIN_MATCH_WINDOW = 32
_FUNC_ALIGNMENT = 16
_MAX_AMBIGUOUS = 3
_MAX_AMBIGUOUS_REPORT = 12  # cap on candidate names kept per ambiguous match

#: Returned when rebrew runs from a wheel install, where no source checkout
#: sits above the package.  A relative name that resolves inside the process
#: cwd, never a guess derived from the module's own location: a wheel's
#: ``parents[2]`` is the interpreter's ``lib/python3.X``, whose parent is a
#: system ``lib`` that could hold an unrelated directory of the same name.
NO_SIGS_CHECKOUT = Path("__no_rebrew_flirt_sigs_checkout__")

#: Where the recondb signature library lives.  It is not a public repository: a
#: checkout needs access to it.
FLIRT_SIGS_REPO_URL = "https://github.com/relumea/recondb"

#: What a user without a recondb checkout is told: the library is not public,
#: and what rebrew reads instead.
_NO_LIBRARY_HINT = (
    f"the recondb signature library ({FLIRT_SIGS_REPO_URL}) is not public: point "
    f"{REBREW_FLIRT_SIGS_DIR_ENV} at a checkout you have access to; without one only the "
    "project's own flirt_sigs/ is read"
)

#: The ``schema_version`` of the ``sigs/index.json`` rebrew reads (published as
#: ``sigs/index.schema.json``), and the first recondb release that writes it: each
#: file keyed by its path relative to ``sigs/``.  An index without the member or with
#: another value is refused, never read by guessing its shape.
SIGNATURE_INDEX_SCHEMA_VERSION = 3
RECONDB_INDEX_RELEASE = "3.0.0"

#: recondb 3.0.0's table of the signature files it renamed (old and new key,
#: tab-separated, ``#`` comment lines), relative to the checkout.
RECONDB_RENAME_TABLE = "docs/renamed-3.0.0.tsv"


def _flirt_sigs_repo() -> Path:
    """Root of the standalone ReconDB checkout (standard library sigs).

    Defaults to the sibling checkout (same workspace as this repo), located
    through :data:`rebrew.utils.SOURCE_CHECKOUT`; overridable via
    REBREW_FLIRT_SIGS_DIR.  Project-specific sigs stay in the project's own
    ``flirt_sigs/`` and are merged on top.

    Raises :class:`ConfigError` when the env override is not a directory, so a
    typo is reported instead of silently dropping every standard-library
    signature. The ``match`` command turns that into its own error exit.

    A wheel install has no checkout beside it and returns
    :data:`NO_SIGS_CHECKOUT`, which every caller probes with ``.is_dir()``.
    """
    env = os.environ.get(REBREW_FLIRT_SIGS_DIR_ENV, "").strip()
    if env:
        resolved = env_dir_path(REBREW_FLIRT_SIGS_DIR_ENV, env)
        assert resolved is not None  # a non-blank value never resolves to None
        return resolved
    if SOURCE_CHECKOUT is None:
        return NO_SIGS_CHECKOUT
    return SOURCE_CHECKOUT.parent / "recondb"


def _sig_base(root: Path) -> Path:
    """The directory *root*'s signature files are keyed against: its ``sigs/`` when it has one.

    A recondb checkout keeps its signatures under ``sigs/``; a project's
    ``flirt_sigs/`` or an explicit signature directory holds them directly.
    """
    return root / "sigs" if (root / "sigs").is_dir() else root


def _sig_key(path: Path, base: Path) -> str:
    """A signature file's key: its path relative to its root's :func:`_sig_base`.

    recondb's ``index.json`` keys a file the same way (``msvc/vc6/libcmt_vc6.sig``).
    """
    return path.relative_to(base).as_posix()


def _sig_entries(
    dirs: list[Path], listed: Mapping[Path, list[str]] | None = None
) -> list[tuple[Path, str]]:
    """``(base, key)`` for the signature files of *dirs* a scan loads; the file is ``base / key``.

    A base in *listed* is not walked: its files are the keys its ``index.json``
    lists (:func:`_arch_index`), in the order a walk would find them.

    One file per stem in each directory, the ``.sig`` preferred (it carries the
    patterns of the ``.pat`` it was built from, and python-flirt parses it
    ~10,000x faster): the set recondb's ``tools/select_sigs.py``
    ``loaded_files`` defines and indexes.  Two directories may hold files of one
    name with other bytes, so a file is known by its directory and stem relative
    to its base, never by its name alone.  Recursive: recondb groups signatures
    by compiler family (``sigs/<family>/<toolchain>/``).  An earlier root wins
    for the same directory and stem, so a project's own copy under
    ``flirt_sigs/<family>/<toolchain>/`` overrides the shared checkout's.
    """
    seen: dict[tuple[str, str], tuple[Path, str]] = {}
    for root in dirs:
        if not root.is_dir():
            continue
        base = _sig_base(root)
        keys = (listed or {}).get(base)
        for suffix in (".sig", ".pat"):
            found = (
                [_sig_key(path, base) for path in base.rglob(f"*{suffix}")]
                if keys is None
                else [key for key in keys if key.endswith(suffix)]
            )
            # Sorted by path components, as sorting the paths themselves orders them.
            for key in sorted(found, key=lambda k: k.split("/")):
                parent, _, name = key.rpartition("/")
                seen.setdefault((parent, name[: -len(suffix)]), (base, key))
    return list(seen.values())


def signature_files(dirs: list[Path]) -> list[Path]:
    """The signature files of *dirs* a scan loads (:func:`_sig_entries`)."""
    return [base / key for base, key in _sig_entries(dirs)]


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

    try:
        repo = _flirt_sigs_repo()
    except ConfigError as exc:
        error_exit(str(exc), json_mode=json_output)
    if not repo.is_dir():
        if repo == NO_SIGS_CHECKOUT:
            error_exit(
                "no recondb checkout: this rebrew is installed as a package, so no "
                f"source checkout sits beside it; {_NO_LIBRARY_HINT}",
                json_mode=json_output,
            )
        error_exit(f"signature source not found: {repo}; {_NO_LIBRARY_HINT}", json_mode=json_output)
    wanted: set[str] | None = None
    linkage = ""
    if matched_only:
        linkage = _detect_crt_linkage(cfg)
        wanted = _matched_sig_names(linkage)
    dest = Path(cfg.root) / "flirt_sigs"
    dest.mkdir(parents=True, exist_ok=True)
    renamed = _follow_renames(repo, dest)
    copied = 0
    for base, key in _sig_entries([repo]):
        src = base / key
        if wanted is not None and key not in wanted:
            continue
        # The copy keeps the file's key, so the checkout's index still names it
        # and two files of one name in different directories both arrive.
        target = dest / key
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # atomic_write_bytes replaces a dangling symlink planted at *target*
        # instead of writing through it.
        atomic_write_bytes(target, src.read_bytes())
        copied += 1
    total = len(signature_files([dest]))
    if json_output:
        json_print(
            {
                "copied": copied,
                "renamed": renamed,
                "total": total,
                "dir": str(dest),
                "linkage": linkage,
            }
        )
        return
    console.print(f"[green]flirt_sigs/: {copied} copied, {total} total[/green]")


def _follow_renames(repo: Path, dest: Path) -> int:
    """Move the project's copies of files the checkout renamed to their new keys; how many moved.

    A copy keeps its checkout key (``flirt_sigs/<key>``), and the key is what the
    checkout's index filters it by; recondb 3.0.0 renamed 312 files
    (:data:`RECONDB_RENAME_TABLE`), so a copy at an old key would be unlisted.  A
    copy whose new key is already taken stays where it is.  Without the table
    (another checkout) nothing moves.
    """
    table = repo / RECONDB_RENAME_TABLE
    if not table.is_file():
        return 0
    moved = 0
    for line in table.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        old, new = line.split("\t")
        source, target = dest / old, dest / new
        if source.is_file() and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            moved += 1
    return moved


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
    """The keys (:func:`_sig_key`) of the sig files worth copying for *linkage* (best-effort heuristics).

    Unknown linkage keeps everything CRT-ish plus WinAPI; known linkage
    keeps its own CRT family plus WinAPI and drops the other family (a
    static binary never matches msvcrt imports and vice versa).
    """
    names: set[str] = set()
    try:
        repo = _flirt_sigs_repo()
    except ConfigError:
        # Best-effort helper reached only after the caller already validated
        # the same env value, so there is nothing left to report here.
        return names
    if not repo.is_dir():
        return names
    for _base, key in _sig_entries([repo]):
        stem = key.rpartition("/")[2].lower()
        is_crt = stem.startswith(_CRT_STATIC_STEMS + _CRT_DYNAMIC_STEMS)
        if (
            not is_crt
            or not linkage
            or (linkage == "static" and stem.startswith(_CRT_STATIC_STEMS))
            or (linkage == "dynamic" and stem.startswith(_CRT_DYNAMIC_STEMS))
        ):
            names.add(key)  # WinAPI + misc always; CRT iff linkage matches
    return names


class SignatureFileError(RebrewError, ValueError):
    """A ``.sig`` or ``.pat`` file python-flirt cannot parse."""


#: Exceptions a parse never turns into :class:`SignatureFileError`: the process is ending.
_EXITS = (KeyboardInterrupt, SystemExit, GeneratorExit)


def parse_signature_file(path: Path) -> list[Any]:
    """The signatures of one ``.sig`` (binary) or ``.pat`` (text) file.

    Raises :class:`SignatureFileError` for a file python-flirt cannot parse:
    its errors, and its panics, which pyo3 raises as a ``BaseException``
    (``pyo3_runtime.PanicException``) that ``except Exception`` does not catch.
    A ``.pat`` is decoded with ``errors="replace"``, not ``"ignore"``: dropping a
    byte merges distinct names (``b"foo\xe9"`` would become the unrelated ``"foo"``).
    Raises :class:`OSError` when the file cannot be read.
    """
    content = path.read_bytes()
    try:
        if path.suffix.lower() == ".sig":
            return list(flirt.parse_sig(content))
        return list(flirt.parse_pat(content.decode("utf-8", errors="replace")))
    except _EXITS:
        raise
    except BaseException as exc:  # a python-flirt panic is a BaseException
        raise SignatureFileError(f"{path.name} is not a signature file python-flirt reads") from exc


def _parse_sig_files(files: list[Path]) -> list[Any]:
    """Parse each FLIRT signature file, warning (not aborting) on bad ones."""
    if flirt is None:
        warnings.warn("python-flirt not installed — skipping signature scan", stacklevel=2)
        return []
    sigs: list[Any] = []
    for filepath in files:
        try:
            parsed = parse_signature_file(filepath)
        except (OSError, SignatureFileError) as e:
            # One bad file must not abort the whole scan.
            warnings.warn(f"Error loading {filepath}: {e}", stacklevel=2)
            continue
        sigs.extend(parsed)
        console.print(f"Loaded {len(parsed)} signatures from {filepath.name}")
    return sigs


#: BinaryInfo.arch -> the signature index's architecture vocabulary.  Public: `analyze`
#: filters the dossier's FLIRT scan the same way `rebrew library scan-signatures` does.
ARCH_FAMILIES: dict[str, str] = {
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


def _arch_index(dirs: list[Path]) -> tuple[dict[str, str], dict[Path, list[str]]]:
    """``key -> arch`` from the ``index.json`` beside the signatures, and each base that ships one with its keys.

    recondb publishes the architecture of every file it loads (its own
    ``tools/index_sigs.py``) in ``sigs/index.json``, keyed by the file's path
    relative to ``sigs/`` (:func:`_sig_key`); ``""`` is an architecture it could
    not tell, and such a file always loads.  An earlier root's entry wins.  A
    root without an index (a project's ``flirt_sigs/``, a user's own directory)
    has none to read.  Raises :class:`ConfigError` for an index that cannot be
    read, or whose ``schema_version`` is not :data:`SIGNATURE_INDEX_SCHEMA_VERSION`
    (a recondb before :data:`RECONDB_INDEX_RELEASE`).
    """
    index: dict[str, str] = {}
    indexed: dict[Path, list[str]] = {}
    for root in dirs:
        if not root.is_dir():
            continue
        base = _sig_base(root)
        candidate = base / "index.json"
        if not candidate.is_file():
            continue
        try:
            data = json.loads(read_json_text(candidate))
        except (OSError, ValueError) as exc:
            raise ConfigError(f"signature index {candidate} cannot be read: {exc}") from None
        version = data.get("schema_version") if isinstance(data, dict) else None
        if type(version) is not int or version != SIGNATURE_INDEX_SCHEMA_VERSION:
            raise ConfigError(
                f"signature index {candidate} is not schema_version "
                f"{SIGNATURE_INDEX_SCHEMA_VERSION}; update the checkout to recondb "
                f"{RECONDB_INDEX_RELEASE} or later"
            )
        files = data.get("files")
        if not isinstance(files, dict):
            raise ConfigError(f"signature index {candidate} has no object of files")
        indexed[base] = list(files)
        for key, meta in files.items():
            index.setdefault(key, str(meta.get("arch", "") if isinstance(meta, dict) else ""))
    return index, indexed


def load_signatures_for(dirs: list[Path], arch: str = "") -> list[Any]:
    """Load the signatures worth trying for *arch* from *dirs*.

    The whole library is ~12 M patterns and python-flirt builds one matcher
    for everything loaded, which does not fit in memory.  A file the index
    lists under another architecture is skipped when *arch* is known; one it
    lists with an unknown architecture (``""``) loads.  A root with an index is
    not walked: the index is that checkout's list of what it ships, so a file
    it does not list is not loaded and one it lists but the checkout lacks is
    reported unreadable by the parse.  A file under a root
    without an index loads unless another root's index lists its key under
    another architecture (a project's copy of a checkout file).  Raises
    :class:`ConfigError` for an index :func:`_arch_index` refuses.
    """
    index, indexed = _arch_index(dirs)
    entries = _sig_entries(dirs, indexed)
    files: list[Path] = []
    other_arch = 0
    for base, key in entries:
        if key not in index or not arch or index[key] in ("", arch):
            # A key no index lists is under a root without one: every key an index lists is in index.
            files.append(base / key)
        else:
            other_arch += 1
    if other_arch:
        console.print(
            f"Architecture {arch}: skipped {other_arch} signature file(s) that cannot match"
        )
    if not files:
        console.print(
            f"No signature files in {', '.join(str(d) for d in dirs)}; {_NO_LIBRARY_HINT}."
        )
        return []
    return _parse_sig_files(files)


def _capstone_for_arch(arch: str, endian: str = "") -> tuple[int, int]:
    """Capstone ``(cs_arch, mode)`` for a rebrew arch string, via binary_loader."""
    from types import SimpleNamespace

    from rebrew.formats.binary_loader import capstone_config_for

    info: Any = SimpleNamespace(arch=arch, endian=endian)
    return capstone_config_for(info)


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
    its delay slot, ``bx lr``, ``blr``, ``rts``).  Falls back to the byte-window
    heuristic when capstone is unavailable.

    *arch* is a rebrew arch string (``x86_32``, ``mips32``, ``arm32``, …), not
    the signature family — mis-decoding MIPS as x86 silently returns the whole
    4096-byte scan window for every function.
    """
    offset = max(offset, 0)
    max_scan = min(_MAX_FUNC_SCAN, max(0, len(code_data) - offset))
    if max_scan <= 0:
        return 0
    scan_end = offset + max_scan
    try:
        from rebrew.binary.analysis import capstone_handle

        cs_arch, mode = _capstone_for_arch(arch, endian)
        # skipdata keeps an undecodable byte as a `.byte` pseudo-instruction
        # (capstone's default skipdata mnemonic).  Without it capstone stops
        # at that byte, the loop ends with no terminator, and the function is
        # reported as the whole 4096-byte scan window.  The handle is cached
        # per thread: a signature scan calls this once per hit, and building
        # a fresh ``Cs`` costs more than decoding a short function.
        md: Any = capstone_handle(cs_arch, mode, skipdata=True)
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


def _names_at_start(hits: list[Any]) -> list[str]:
    """Distinct names the matched signatures give their first byte, in order.

    A signature's names at other offsets (``:0064@ LeadUpVec``, a label of
    the module or a second entry point) name other addresses, not the match.
    """
    names: dict[str, None] = {}
    for m in hits:
        for n in m.names:
            label, offset = (n[0], n[2]) if isinstance(n, tuple) else (str(n), 0)
            if label and offset == 0:
                names.setdefault(label)
    return list(names)


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
    identification never guesses.  Shared by ``rebrew library scan-signatures``, ``rebrew
    binary analyze``, and ``rebrew library identify``.

    *stride* defaults to :func:`arch_stride` for *arch* (2 for SH2, 4 for the
    other RISC arches, 16 for x86); function sizes are decoded with the same
    architecture and *endian*
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
        names = _names_at_start(hits)
        if not names or len(names) > max_ambiguous:
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
        "  rebrew library scan-signatures  # Scan with default .sig files\n\n"
        "  rebrew library scan-signatures sigs/  # Use custom signature directory\n\n"
        "  rebrew library scan-signatures --json  # Output matches as JSON\n\n"
        "  # Only report functions ≥32 bytes\n"
        "  rebrew library scan-signatures --min-size 32\n\n"
        "[bold]How it works:[/bold]\n\n"
        "  Scans the target binary using FLIRT (Fast Library Identification and Recognition Technology) signatures to identify known library functions (MSVCRT, DirectX, Zlib, etc.).\n\n"
        "[dim]Signatures load from the project's flirt_sigs/ merged with the recondb checkout (REBREW_FLIRT_SIGS_DIR overrides); or pass a SIG_DIR argument. Reads target binary path from rebrew-project.toml.[/dim]"
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
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """FLIRT signature scanner for binaries."""
    cfg = require_config(target=target, json_mode=json_output)

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
    arch = ARCH_FAMILIES.get(native_arch, "")

    # 2. Load FLIRT signatures: an explicit dir, else the project flirt_sigs/
    # merged with the recondb checkout (standard library sigs).
    try:
        if sig_dir is not None:
            sig_roots = [Path(sig_dir)]
        else:
            sig_roots = [cfg.root / "flirt_sigs", _flirt_sigs_repo()]
        sigs = load_signatures_for(sig_roots, arch)
    except ConfigError as exc:
        error_exit(str(exc), json_mode=json_output)
    sig_sources = [str(root) for root in sig_roots]
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
        names = _names_at_start(hits)
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


def init_signatures(
    matched_only: bool = typer.Option(
        False,
        "--matched-only",
        help="Copy only signatures for the detected CRT linkage plus WinAPI imports",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Copy the shared signatures into flirt_sigs/; keep existing project files."""
    cfg = require_config(target=target, json_mode=json_output)
    _init_project_sigs(cfg, json_output, matched_only=matched_only)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
