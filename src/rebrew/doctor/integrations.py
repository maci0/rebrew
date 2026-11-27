"""Optional tooling, integration checks, orchestration, and rendering for doctor."""

import logging
from datetime import UTC, datetime, timedelta
lazy from pathlib import Path
lazy from typing import Any

lazy import typer
lazy from rich.panel import Panel
lazy from rich.text import Text

import rebrew.doctor.checks as checks_mod
from rebrew.cli import console
from rebrew.doctor.checks import (
    FAIL,
    OK,
    SKIP,
    WARN,
    CheckResult,
    DoctorReport,
    LibIndexUnavailable,
    check_arch_format,
    check_backup_readiness,
    check_bin_dir,
    check_cache_backend,
    check_compiler,
    check_config_parse,
    check_external_libs,
    check_function_bindings,
    check_function_list,
    check_includes,
    check_layout_package,
    check_libs,
    check_metadata_files,
    check_runner,
    check_shared_sources,
    check_source_files,
    check_target_binary,
    check_toolchain_alignment,
    check_toolchain_backed,
    resolve_pkg_hook,
)
lazy from rebrew.config import ProjectConfig
lazy from rebrew.utils import TerminalTable, md5_file, read_json_text, try_parse_int

logger = logging.getLogger(__name__)

#: BinSync state dir with no commit for longer than this is reported stale.
_BINSYNC_STALE_AFTER = timedelta(days=14)

_STATUS_ICONS = {
    OK: "\u2705",
    FAIL: "\u274c",
    WARN: "\u26a0\ufe0f",
    SKIP: "\u23ed\ufe0f",
}

_STATUS_STYLES = {
    OK: "green",
    FAIL: "red",
    WARN: "yellow",
    SKIP: "dim",
}


# ---------------------------------------------------------------------------
# Integration and toolchain-fingerprint checks
# ---------------------------------------------------------------------------


def _prove_install_fix(
    *,
    optional: bool,
    checkout_install: str = "uv sync --extra prove",
    tool_install: str = "uv tool install --with angr rebrew",
) -> str:
    """Install hint for the environment ``rebrew doctor`` actually imports."""
    prefix = "Optional: " if optional else "Install the prove extra: "
    return (
        f"{prefix}{tool_install}. "
        f"From a checkout: {checkout_install}. "
        "Doctor probes the environment of the rebrew command."
    )


def check_optional_tools(
    *,
    angr_available_fn: Any = None,
    checkout_install: str = "uv sync --extra prove",
    tool_install: str = "uv tool install --with angr rebrew",
) -> CheckResult:
    """Check angr and its bundled Claripy solver for symbolic proving.

    Import the solver to catch missing or broken optional installations.
    """
    has_angr = bool(angr_available_fn()) if angr_available_fn is not None else False
    claripy_available = False
    angr_logger = logging.getLogger("angr")
    previous_level = angr_logger.level
    angr_logger.setLevel(logging.CRITICAL)  # optional unicorn import logs an irrelevant error
    try:
        from angr import claripy  # noqa: F401  # presence probe; name unused

        claripy_available = True
    except ImportError:
        pass
    finally:
        angr_logger.setLevel(previous_level)

    if has_angr and claripy_available:
        return CheckResult(
            name="Optional tools",
            status=OK,
            message="angr + claripy available (for 'rebrew prove')",
        )
    if has_angr:
        return CheckResult(
            name="Optional tools",
            status=WARN,
            message="angr installed but claripy is missing — prove will crash",
            fix=_prove_install_fix(
                optional=False, checkout_install=checkout_install, tool_install=tool_install
            ),
        )
    return CheckResult(
        name="Optional tools",
        status=WARN,
        message="angr + claripy missing (for 'rebrew prove')",
        fix=_prove_install_fix(
            optional=True, checkout_install=checkout_install, tool_install=tool_install
        ),
    )


def check_decompilers() -> CheckResult:
    """Which packaged decompiler backends can run here (``rebrew.decompiler.cli_backend_state``).

    The same states ``rebrew.vocabulary`` reports for the engine; Ghidra is
    probed at the configured endpoint, else the default every ``--endpoint`` offers.
    """
    from rebrew.decompiler import PACKAGED_BACKEND_MAP, REASON_TEXT, cli_backend_state

    states = [cli_backend_state(name) for name in PACKAGED_BACKEND_MAP]
    available = [state.name for state in states if state.reason is None]
    missing = [f"{state.name} ({REASON_TEXT[state.reason]})" for state in states if state.reason]
    message = f"available: {', '.join(available) or 'none'}"
    if missing:
        message += f"; not available: {'; '.join(missing)}"
    return CheckResult(
        name="Decompilers",
        status=OK if available else WARN,
        message=message,
        fix=""
        if available
        else "Install kuna or rizin with rz-ghidra, or configure Ghidra "
        "(REBREW_GHIDRA_MCP_ENDPOINT), to decompile.",
    )


def _flirt_problem_fix(problems: list[str]) -> str:
    """Tell empty pattern files apart from files that fail to parse.

    A ``---``-only ``.pat`` has no patterns. Import libraries produce that
    result, and deleting the file is the repair. A parse error is the file
    to regenerate.
    """
    empty = [item for item in problems if "(0 signatures)" in item]
    corrupt = [item for item in problems if item not in empty]
    parts: list[str] = []
    if empty:
        parts.append(
            "Remove signature files with 0 signatures "
            "(import libraries have no code to sign): " + "; ".join(empty)
        )
    if corrupt:
        parts.append(
            "Regenerate corrupt .pat files with 'rebrew library signatures': " + "; ".join(corrupt)
        )
    return " ".join(parts)


def check_flirt_sigs(cfg: ProjectConfig, *, parse_signature_fn: Any = None) -> CheckResult:
    """Check the ``flirt_sigs/`` directory: present, non-empty, and every
    ``.pat``/``.sig`` file actually parses via python-flirt — the exact reader
    ``rebrew library scan-signatures`` uses.

    A directory full of corrupt or legacy signatures silently yields zero
    matches; this check surfaces that before the user wastes a scan.
    """
    sig_dir = cfg.root / "flirt_sigs"
    if not sig_dir.exists():
        return CheckResult(
            name="FLIRT signatures",
            status=WARN,
            message="flirt_sigs/ directory not found",
            fix=(
                "Run 'rebrew library init-signatures --matched-only' for the linkage-matched "
                "set, or generate from a compiler .lib with "
                "'rebrew library signatures /path/to/msvcrt.lib "
                "--output flirt_sigs/msvcrt_vc6.pat'."
            ),
        )

    sig_files = sorted(sig_dir.rglob("*.pat")) + sorted(sig_dir.rglob("*.sig"))
    if not sig_files:
        return CheckResult(
            name="FLIRT signatures",
            status=WARN,
            message="flirt_sigs/ exists but contains no .pat/.sig files",
            fix="Add signatures as described above.",
        )

    try:
        import flirt  # noqa: F401  # presence probe; the parse goes through rebrew.library.flirt
    except ImportError:
        return CheckResult(
            name="FLIRT signatures",
            status=SKIP,
            message=f"{len(sig_files)} sig file(s) found, but python-flirt is not installed",
            fix="Install python-flirt to use 'rebrew library scan-signatures': 'uv add python-flirt'.",
        )
    if parse_signature_fn is None:
        return CheckResult(
            name="FLIRT signatures",
            status=SKIP,
            message="FLIRT signature parser not configured",
        )

    total = 0
    problems: list[str] = []
    for filepath in sig_files:
        try:
            if filepath.suffix == ".pat":
                # Strict: rebrew writes .pat as UTF-8, so an undecodable
                # byte is corruption (the scan paths would show it as U+FFFD).
                filepath.read_bytes().decode("utf-8")
            parsed = parse_signature_fn(filepath)
            total += len(parsed)
            if not parsed:
                problems.append(f"{filepath.name} (0 signatures)")
        except (OSError, ValueError) as e:  # SignatureFileError and UnicodeDecodeError among them
            problems.append(f"{filepath.name} (corrupt: {e})")

    if problems:
        return CheckResult(
            name="FLIRT signatures",
            status=WARN,
            message=f"{len(sig_files)} file(s), {total} sigs load; {len(problems)} problem file(s)",
            fix=_flirt_problem_fix(problems),
        )
    return CheckResult(
        name="FLIRT signatures",
        status=OK,
        message=f"{len(sig_files)} file(s), {total} signatures load",
    )


def check_ghidra_sync(cfg: ProjectConfig) -> CheckResult:
    """Check the Ghidra sync setup: backend config, program path, and (for
    the ghidra-cli backend) the binary's presence."""
    backend = getattr(cfg, "ghidra_backend", "reva")
    program_path = getattr(cfg, "ghidra_program_path", "")

    if backend == "cli":
        from rebrew.ghidra import resolve_ghidra_cli

        found = resolve_ghidra_cli(cfg)
        if found is None:
            return CheckResult(
                name="Ghidra sync",
                status=WARN,
                message="ghidra_backend = 'cli' but no ghidra-cli binary found",
                fix=(
                    "Install ghidra-cli (cargo install ghidra-cli) or place the "
                    "binary at tools/ghidra-cli."
                ),
            )
        if not program_path:
            return CheckResult(
                name="Ghidra sync",
                status=WARN,
                message=f"ghidra-cli found ({found}), but ghidra_program_path is not set",
                fix="Set targets.<name>.ghidra_program_path in rebrew-project.toml.",
            )
        return CheckResult(
            name="Ghidra sync",
            status=OK,
            message=f"ghidra-cli backend ready ({found})",
        )

    # ReVa (MCP) backend.
    if not program_path:
        return CheckResult(
            name="Ghidra sync",
            status=WARN,
            message="ghidra_program_path is not set — sync may target the wrong program",
            fix="Set targets.<name>.ghidra_program_path in rebrew-project.toml.",
        )
    return CheckResult(
        name="Ghidra sync",
        status=OK,
        message=f"ReVa backend ready (program: {program_path})",
    )


def check_binsync_state(cfg: ProjectConfig) -> CheckResult:
    """Check the BinSync field-sync state dir (the Ghidra relay health).

    Field sync goes through the shared BinSync state dir; the BinSync
    Ghidra plugin relays it to/from Ghidra.  This surfaces the "state was
    exported but Ghidra never sees it" failure mode: a missing dir, a
    non-git dir (the plugin workflow expects a git-versioned state), or a
    stale dir (nothing committed recently — the plugin is not relaying).
    """
    state = getattr(cfg, "binsync_state_dir", "") or ""
    if not state:
        return CheckResult(
            name="BinSync sync",
            status=WARN,
            message="no BinSync state dir configured — field sync requires "
            "--state-dir or targets.<name>.binsync_state_dir",
            fix="Set targets.<name>.binsync_state_dir in rebrew-project.toml "
            "(or pass --state-dir to rebrew sync push).",
        )
    from rebrew.binsync.serial import declib_available

    if not declib_available():
        return CheckResult(
            name="BinSync sync",
            status=FAIL,
            message="BinSync state dir configured but declib (the binsync extra) is not "
            "installed — every sync push/pull/summary exits before writing",
            fix="uv sync --extra binsync (or reinstall the tool as 'rebrew[binsync]').",
        )
    state_path = Path(state).expanduser()
    if not state_path.exists():
        return CheckResult(
            name="BinSync sync",
            status=WARN,
            message=f"configured BinSync state dir not found: {state}",
            fix="Export it once with 'rebrew sync push --state-dir <dir>'.",
        )
    if not state_path.is_dir():
        return CheckResult(
            name="BinSync sync",
            status=WARN,
            message=f"configured BinSync state path is not a directory: {state}",
            fix="Point binsync_state_dir at the state directory.",
        )
    # A BinSync-authored state dir records the MD5 of the binary it belongs to
    # at its root (``binary_hash``).  When that disagrees with this target's
    # binary, every address in the state names a different binary, so the relay
    # would bind another binary's symbols to this target's VAs.
    hash_file = state_path / "binary_hash"
    binary = getattr(cfg, "target_binary", None)
    if hash_file.exists() and binary is not None and Path(binary).exists():
        try:
            stored = hash_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            # Present but unreadable is not the same as absent: reading it as
            # "" would short-circuit the comparison below and fall through to
            # PASS, hiding a state dir whose addresses may name another binary.
            return CheckResult(
                name="BinSync sync",
                status=WARN,
                message=f"could not read {hash_file} in BinSync state dir {state}: {exc}",
                fix="Fix the file's permissions, or point binsync_state_dir at a "
                "readable state dir for this target.",
            )
        if stored and stored.lower() != md5_file(Path(binary)):
            return CheckResult(
                name="BinSync sync",
                status=WARN,
                message=f"BinSync state dir {state} belongs to a different binary "
                "(binary_hash mismatch) — its addresses do not name this target",
                fix="Point binsync_state_dir at this target's state dir, or export "
                "a fresh one for this binary.",
            )
    # The BinSync workflow expects a git-versioned shared state (the plugin
    # commits/rebase-pulls it).  Without git, the relay cannot sync back.
    git_dir = state_path / ".git"
    if not git_dir.exists():
        return CheckResult(
            name="BinSync sync",
            status=WARN,
            message=f"BinSync state dir {state} is not a git repository — the "
            "plugin workflow expects a versioned shared state",
            fix="git init the state dir (or clone the team's state repo).",
        )
    # Staleness: if nothing has been committed recently, the plugin (or a
    # collaborator) is not relaying — Ghidra will never see the export.
    last: datetime | None = None
    try:
        from rebrew.binsync.git import run_git

        proc = run_git(state_path, "log", "-1", "--format=%ct", timeout=10)
        if proc.returncode == 0 and proc.stdout.strip():
            last = datetime.fromtimestamp(int(proc.stdout.strip()), tz=UTC)
    # OSError, not ValueError: a %ct outside the platform's range raises
    # [Errno 75] on Windows and musl.  A commit stamped years ahead (a
    # clock-skewed CI commit, GIT_COMMITTER_DATE set forward) reaches that.
    except OSError, ValueError, OverflowError:
        last = None
    if last is not None:
        # Absolute elapsed time between UTC instants: DST on the host cannot
        # shrink or stretch the threshold.
        age = datetime.now(UTC) - last
        if age > _BINSYNC_STALE_AFTER:
            return CheckResult(
                name="BinSync sync",
                status=WARN,
                message=f"BinSync state dir {state} has not been committed in "
                f"{age.days} days — the BinSync Ghidra plugin may not be "
                "relaying (Ghidra will not see exports)",
                fix="Check that the BinSync Ghidra plugin is installed and "
                "watching this state dir.",
            )
    else:
        # No commit timestamp (empty repo, unreadable history): the relay
        # state is unchecked — never report it as ready.
        return CheckResult(
            name="BinSync sync",
            status=WARN,
            message=f"BinSync state dir {state} has no commits yet — sync state "
            "is unchecked (Ghidra may not see exports)",
            fix="Export once with 'rebrew sync push --state-dir <dir>' and "
            "confirm the BinSync Ghidra plugin is watching this state dir.",
        )
    return CheckResult(
        name="BinSync sync",
        status=OK,
        message=f"BinSync state dir ready ({state})",
    )


def check_crt_linkage(cfg: ProjectConfig) -> CheckResult:
    """Check that base_cflags matches the binary's detected CRT linkage.

    A dynamic CRT (``msvcrt.dll`` import) needs ``/MD``; a statically
    linked CRT needs ``/MT``.  Compiling libc-calling functions with the
    wrong linkage breaks byte-matching at every CRT call site (memcpy
    becomes a rel32 call instead of an IAT call), so flag the mismatch
    with the fix.
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return CheckResult(name="CRT linkage", status=SKIP, message="binary not available")
    profile = getattr(cfg, "compiler_profile", "") or ""
    if not profile.startswith("msvc"):
        return CheckResult(name="CRT linkage", status=SKIP, message="non-msvc profile")

    from rebrew.toolchain_detect import detect_toolchain

    try:
        info = detect_toolchain(binary)
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(name="CRT linkage", status=SKIP, message=f"detection failed: {exc}")
    if not info.base_cflags:
        return CheckResult(name="CRT linkage", status=SKIP, message="CRT linkage not identifiable")

    base_cflags = getattr(cfg, "base_cflags", "") or ""
    detected = info.base_cflags  # e.g. "/MD" or "/MT"
    # Whole-token compare: "/MD" is a prefix of the debug spellings "/MDd"
    # and "/MTd", which link a different CRT than the detector reported.
    if detected in base_cflags.replace("/", " /").split():
        return CheckResult(
            name="CRT linkage",
            status=OK,
            message=f"{info.crt} ({info.crt_linkage}) — base_cflags matches ({detected})",
        )
    return CheckResult(
        name="CRT linkage",
        status=WARN,
        message=f"{info.crt} ({info.crt_linkage}) needs base_cflags {detected}, "
        f"project has '{base_cflags or '(unset)'}'",
        fix=f'Set base_cflags = "/nologo /c {detected}" in rebrew-project.toml',
    )


def inventory_spans(cfg: Any) -> list[tuple[int, int]]:
    """``(va, size)`` rows from the target inventory, or none when it is absent."""
    import json

    from rebrew.config import inventory_path_for

    reversed_dir = getattr(cfg, "reversed_dir", "") or ""
    path = inventory_path_for(reversed_dir, cfg) if reversed_dir else Path()
    if not path.is_file():
        raw = str(getattr(cfg, "inventory_file", "") or "").strip()
        root = getattr(cfg, "root", None)
        if raw and root:
            path = Path(root) / raw
    if not path.is_file():
        return []
    try:
        rows = json.loads(read_json_text(path))
    except OSError, ValueError:
        return []
    spans: list[tuple[int, int]] = []
    if not isinstance(rows, list):
        return []
    for row in rows:
        if not isinstance(row, dict):
            continue
        start = try_parse_int(row.get("va"))
        size = try_parse_int(row.get("size"))
        if start is not None and size is not None and size > 0:
            spans.append((start, size))
    spans.sort()
    return spans


def _span_at(spans: list[tuple[int, int]], va: int) -> tuple[int, int] | None:
    for start, size in spans:
        if start <= va < start + size:
            return start, size
        if start > va:
            break
    return None


def libcmt_index(cfg: Any, *, match_helpers: tuple[Any, ...] | None = None) -> Any:
    """Indexed stock LIBCMT.

    ``None`` when no archive applies (no profile, or the container runtime
    that could extract one is absent), which is a skip.  An archive that is
    there and unreadable is an error: :class:`LibIndexUnavailable` for a read
    failure, and whatever ``index_library`` raises for a parse failure, so the
    caller reports the cause instead of judging the flag on unrefined data.
    """
    if match_helpers is None:
        return None
    ensure_stock_lib, index_library, stock_lib_cache = match_helpers[:3]

    name = "LIBCMT.LIB"
    profile = str(getattr(cfg, "compiler_profile", "") or "")
    cached = stock_lib_cache(Path(cfg.root), name, profile)
    try:
        if not profile or not ensure_stock_lib(cached, profile=profile, name=name):
            return None
        return index_library(cached)
    except typer.Exit:
        # index_library reports an unparsable archive through error_exit, which
        # has already written the error envelope to stdout and picked the exit
        # code. Absorbing the Exit would leave that object inside doctor's
        # --json document and let the check go on to report a confident result
        # computed without the library refinement.
        raise
    except (OSError, ValueError) as exc:
        raise LibIndexUnavailable(f"cannot read {cached}: {exc}") from exc


def library_site_counts(
    cfg: Any, info: Any, *, match_helpers: tuple[Any, ...] | None = None
) -> tuple[int, int] | None:
    """How many of *info*'s wrapper sites sit in a stock LIBCMT body.

    None when the archive does not apply or the inventory is unavailable, so
    the caller keeps the whole-image reading.  Raises
    :class:`LibIndexUnavailable` when an archive is present but unreadable.
    """
    if match_helpers is None:
        return None
    from rebrew.formats.binary_loader import extract_raw_bytes

    prefix_bytes, match_bytes, match_leading_body = match_helpers[3:6]

    spans = inventory_spans(cfg)
    sites = list(getattr(info, "o2_wrapper_sites", ()) or ()) + list(
        getattr(info, "o1_wrapper_sites", ()) or ()
    )
    if not spans or not sites:
        return None
    index = libcmt_index(cfg, match_helpers=match_helpers)
    if not index:
        return None
    binary = Path(cfg.target_binary)
    matched: dict[int, bool] = {}

    def in_library(va: int) -> bool:
        span = _span_at(spans, va)
        if span is None:
            return False
        start, size = span
        if start not in matched:
            try:
                data = extract_raw_bytes(binary, start, size)
            except OSError:
                matched[start] = False
            else:
                hit = match_bytes(index, data)
                if not hit and size > prefix_bytes:
                    hit = match_bytes(index, extract_raw_bytes(binary, start, prefix_bytes))
                if not hit:
                    hit = match_leading_body(index, data)
                matched[start] = bool(hit)
        return matched[start]

    lib_o2 = sum(1 for va in info.o2_wrapper_sites if in_library(va))
    lib_o1 = sum(1 for va in info.o1_wrapper_sites if in_library(va))
    return lib_o2, lib_o1


_DEFAULT_LIBRARY_SITE_COUNTS = library_site_counts


def check_opt_level(cfg: ProjectConfig, *, exclude_ranges_fn: Any = None) -> CheckResult:
    """Check the project's optimization flag against the binary's detected one.

    MSVC /O1 vs /O2 produce different argument-passing codegen for wrapper
    functions (push-[mem] + pop ecx vs load-first + add esp), so compiling
    with the wrong level silently breaks byte-matching at every wrapper call
    site.  The detection fingerprint (see toolchain_detect) reports the
    dominant level — or "mixed" when the binary was built with per-file /O
    overrides, in which case a project-wide flag cannot be right and the
    user should flag-sweep per function.

    A statically linked LIBCMT keeps the /O it was built with. Those sites
    are removed before the project flag is judged, so a /O2 program linked
    to an /O1 CRT is not reported as a mixed compile.
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return CheckResult(name="Optimization level", status=SKIP, message="binary not available")
    profile = getattr(cfg, "compiler_profile", "") or ""
    if not profile.startswith("msvc"):
        return CheckResult(name="Optimization level", status=SKIP, message="non-msvc profile")

    from rebrew.toolchain_detect import detect_toolchain, opt_level_without_library

    try:
        excluded = exclude_ranges_fn(cfg) if exclude_ranges_fn is not None else []
        info = detect_toolchain(binary, exclude_ranges=excluded)
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(
            name="Optimization level", status=SKIP, message=f"detection failed: {exc}"
        )
    crt_note = ""
    if (
        info.opt_level is not None
        and info.opt_level.startswith("mixed")
        and getattr(info, "crt", "") == "LIBCMT"
        and getattr(info, "crt_linkage", "") == "static"
    ):
        site_counts_fn = resolve_pkg_hook(
            "_library_site_counts", library_site_counts, _DEFAULT_LIBRARY_SITE_COUNTS
        )
        try:
            counts = site_counts_fn(cfg, info)
        except LibIndexUnavailable as exc:
            return CheckResult(
                name="Optimization level", status=SKIP, message=f"stock LIBCMT unusable: {exc}"
            )
        if counts is not None:
            refined = opt_level_without_library(
                len(info.o2_wrapper_sites), len(info.o1_wrapper_sites), counts[0], counts[1]
            )
            if refined is not None and not refined.startswith("mixed"):
                info.opt_level = refined or None
                crt_note = f" (static {info.crt} carries the other wrapper style)"
    if not info.opt_level:
        message = "codegen fingerprint inconclusive (no wrapper-style evidence)"
        if crt_note:
            message = f"no program wrapper sites{crt_note}"
        return CheckResult(
            name="Optimization level",
            status=SKIP,
            message=message,
        )

    cflags = getattr(cfg, "cflags", "") or ""
    if info.opt_level.startswith("mixed"):
        # Mixed build: no single project flag is right.  Only flag when the
        # project pins one level (a hint, not an error — the user may be
        # mid-sweep).
        if "/O1" in cflags or "/O2" in cflags:
            return CheckResult(
                name="Optimization level",
                status=WARN,
                message=f"binary shows {info.opt_level} wrapper styles — project cflags "
                f"'{cflags}' can only match one half; use per-function flag sweeps",
                fix="rebrew match flags <file>",
            )
        return CheckResult(
            name="Optimization level",
            status=OK,
            message=f"{info.opt_level} detected — project uses per-function flags",
        )

    detected = info.opt_level  # "/O1" or "/O2"
    if detected in cflags:
        return CheckResult(
            name="Optimization level",
            status=OK,
            message=f"binary fingerprint shows {detected}{crt_note} — cflags matches",
        )
    return CheckResult(
        name="Optimization level",
        status=WARN,
        message=f"binary fingerprint shows {detected}, project cflags is '{cflags or '(unset)'}'",
        fix=f'Set compiler cflags to "{detected}" in rebrew-project.toml (or per-function metadata)',
    )


# ---------------------------------------------------------------------------
# Main diagnostic runner and renderer
# ---------------------------------------------------------------------------


_DEFAULT_CORE_CHECKS: dict[str, Any] = {
    "check_config_parse": check_config_parse,
    "check_target_binary": check_target_binary,
    "check_arch_format": check_arch_format,
    "check_toolchain_alignment": check_toolchain_alignment,
    "check_cache_backend": check_cache_backend,
    "check_toolchain_backed": check_toolchain_backed,
    "check_compiler": check_compiler,
    "check_runner": check_runner,
    "check_includes": check_includes,
    "check_libs": check_libs,
    "check_function_list": check_function_list,
    "check_source_files": check_source_files,
    "check_bin_dir": check_bin_dir,
    "check_metadata_files": check_metadata_files,
    "check_function_bindings": check_function_bindings,
    "check_shared_sources": check_shared_sources,
    "check_external_libs": check_external_libs,
    "check_layout_package": check_layout_package,
    "check_backup_readiness": check_backup_readiness,
}

_DEFAULT_INTEGRATION_CHECKS: dict[str, Any] = {
    "check_crt_linkage": check_crt_linkage,
    "check_opt_level": check_opt_level,
    "check_optional_tools": check_optional_tools,
    "check_decompilers": check_decompilers,
    "check_flirt_sigs": check_flirt_sigs,
    "check_ghidra_sync": check_ghidra_sync,
    "check_binsync_state": check_binsync_state,
}


def _resolve_check(name: str) -> Any:
    if name in _DEFAULT_CORE_CHECKS:
        return resolve_pkg_hook(name, getattr(checks_mod, name), _DEFAULT_CORE_CHECKS[name])
    return resolve_pkg_hook(name, globals()[name], _DEFAULT_INTEGRATION_CHECKS[name])


def run_doctor(target: str | None = None) -> DoctorReport:
    """Run all diagnostic checks and return a report."""
    report = DoctorReport()

    config_result, cfg = _resolve_check("check_config_parse")(target=target)
    report.checks.append(config_result)
    if cfg is None:
        report.target = target or "(unknown)"
        return report

    report.target = cfg.target_name

    report.checks.append(_resolve_check("check_target_binary")(cfg))
    report.checks.append(_resolve_check("check_arch_format")(cfg))
    report.checks.append(_resolve_check("check_toolchain_alignment")(cfg))
    report.checks.append(_resolve_check("check_cache_backend")(cfg))
    # Project-level config vs binary fingerprints: CRT linkage + opt-level
    # are kept in doctor because they diagnose "you configured the wrong
    # toolchain shape" before any corpus exists.  Per-function metadata
    # checks (e.g. redundant cflags) live in `rebrew lint` (W029).
    report.checks.append(_resolve_check("check_crt_linkage")(cfg))
    report.checks.append(_resolve_check("check_opt_level")(cfg))
    report.checks.append(_resolve_check("check_toolchain_backed")(cfg))
    report.checks.append(_resolve_check("check_compiler")(cfg))
    report.checks.append(_resolve_check("check_runner")(cfg))
    report.checks.append(_resolve_check("check_includes")(cfg))
    report.checks.append(_resolve_check("check_libs")(cfg))
    report.checks.append(_resolve_check("check_function_list")(cfg))
    report.checks.append(_resolve_check("check_source_files")(cfg))
    report.checks.append(_resolve_check("check_bin_dir")(cfg))
    report.checks.append(_resolve_check("check_metadata_files")(cfg))
    report.checks.append(_resolve_check("check_function_bindings")(cfg))
    report.checks.append(_resolve_check("check_shared_sources")(cfg))
    report.checks.append(_resolve_check("check_external_libs")(cfg))
    report.checks.append(_resolve_check("check_layout_package")(cfg))
    report.checks.append(_resolve_check("check_optional_tools")())
    report.checks.append(_resolve_check("check_decompilers")())
    report.checks.append(_resolve_check("check_flirt_sigs")(cfg))
    report.checks.append(_resolve_check("check_ghidra_sync")(cfg))
    report.checks.append(_resolve_check("check_binsync_state")(cfg))
    report.checks.append(_resolve_check("check_backup_readiness")(cfg))

    return report


_DEFAULT_CONSOLE = console


def render_doctor(report: DoctorReport) -> None:
    """Print the doctor panel. The title is the target name, not a filesystem path."""
    out = resolve_pkg_hook("console", console, _DEFAULT_CONSOLE)
    table = TerminalTable(show_header=True, header_style="bold", pad_edge=False, expand=False)
    table.add_column("", width=2, no_wrap=True)
    table.add_column("Check", width=20, no_wrap=True, overflow="ellipsis")
    table.add_column("Message", overflow="fold")
    table.add_column("Fix", overflow="fold", style="dim")

    for check in report.checks:
        icon = _STATUS_ICONS.get(check.status, "?")
        style = _STATUS_STYLES.get(check.status, "")
        table.add_row(
            icon,
            Text(check.name, style=style),
            Text(check.message, style=style),
            Text(check.fix or ""),
        )

    parts = []
    if report.pass_count:
        parts.append(f"[green]{report.pass_count} passed[/green]")
    if report.fail_count:
        parts.append(f"[red]{report.fail_count} failed[/red]")
    if report.warn_count:
        parts.append(f"[yellow]{report.warn_count} warnings[/yellow]")

    border = "green" if report.passed else "red"
    panel = Panel(
        table,
        title=f"Rebrew Doctor — target: {report.target}",
        subtitle="  ".join(parts),
        border_style=border,
    )
    out.print(panel)

    if report.passed:
        out.print("[green]  Project looks healthy![/green]")
    else:
        out.print("[red]  Issues found. Fix the failures above and re-run.[/red]")
