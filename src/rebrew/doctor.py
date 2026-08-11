"""doctor.py – Diagnostic command for rebrew project health.

Validates the entire toolchain in a single command: config file, target
binary, compiler paths, include/lib directories, function list, and
source files.  Prints a checklist with actionable fix suggestions.

Usage::

    rebrew doctor
    rebrew doctor --target client_exe
    rebrew doctor --json
"""

import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rebrew.cli import EXIT_MISMATCH, TargetOption, json_print, require_config
from rebrew.config import ProjectConfig, load_config

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Check result data
# ---------------------------------------------------------------------------

_PASS = "pass"
_FAIL = "fail"
_WARN = "warn"
_SKIP = "skip"


@dataclass
class CheckResult:
    """Result of a single diagnostic check."""

    name: str
    status: str  # "pass", "fail", "warn", "skip"
    message: str
    fix: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize to a plain dict for JSON output."""
        d: dict[str, str] = {
            "name": self.name,
            "status": self.status,
            "message": self.message,
        }
        if self.fix:
            d["fix"] = self.fix
        return d


@dataclass
class DoctorReport:
    """Aggregated results from all diagnostic checks."""

    target: str = ""
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if no checks failed."""
        return all(c.status != _FAIL for c in self.checks)

    @property
    def pass_count(self) -> int:
        """Number of checks that passed."""
        return sum(1 for c in self.checks if c.status == _PASS)

    @property
    def fail_count(self) -> int:
        """Number of checks that failed."""
        return sum(1 for c in self.checks if c.status == _FAIL)

    @property
    def warn_count(self) -> int:
        """Number of checks with warnings."""
        return sum(1 for c in self.checks if c.status == _WARN)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "target": self.target,
            "passed": self.passed,
            "summary": {
                "pass": self.pass_count,
                "fail": self.fail_count,
                "warn": self.warn_count,
            },
            "checks": [c.to_dict() for c in self.checks],
        }


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

_KNOWN_FORMATS = {"pe", "elf", "macho"}
_KNOWN_ARCHES = {"x86_32", "x86_64", "arm32", "arm64"}


def check_config_parse(target: str | None) -> tuple[CheckResult, ProjectConfig | None]:
    """Check that rebrew-project.toml exists and parses without errors."""
    try:
        cfg = load_config(target=target)
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=_PASS,
                message=f"Parsed successfully (target: {cfg.target_name})",
            ),
            cfg,
        )
    except FileNotFoundError as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=_FAIL,
                message=str(e),
                fix="Run 'rebrew init' to create a new project, or cd into a project directory.",
            ),
            None,
        )
    except KeyError as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=_FAIL,
                message=f"Config error: {e}",
                fix="Check rebrew-project.toml for missing [targets] section or invalid target name.",
            ),
            None,
        )
    except (ValueError, TypeError, OSError) as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=_FAIL,
                message=f"Unexpected error: {e}",
                fix="Check rebrew-project.toml syntax (must be valid TOML).",
            ),
            None,
        )


def check_target_binary(cfg: ProjectConfig) -> CheckResult:
    """Check that the target binary exists and is loadable."""
    bin_path: Path = cfg.target_binary
    if not bin_path.exists():
        return CheckResult(
            name="Target binary",
            status=_FAIL,
            message=f"Not found: {bin_path}",
            fix=f"Place the target binary at '{bin_path}' or update 'binary' in rebrew-project.toml.",
        )

    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path, fmt=cfg.binary_format)
        sections = len(info.sections)
        return CheckResult(
            name="Target binary",
            status=_PASS,
            message=(
                f"Loaded {cfg.binary_format.upper()} "
                f"(base=0x{info.image_base:X}, "
                f".text=0x{info.text_va:X}, "
                f"{sections} sections)"
            ),
        )
    except (ValueError, FileNotFoundError, OSError) as e:
        return CheckResult(
            name="Target binary",
            status=_FAIL,
            message=f"Failed to load: {e}",
            fix="Check the 'format' field in rebrew-project.toml matches the actual binary format.",
        )


def check_arch_format(cfg: ProjectConfig) -> CheckResult:
    """Validate arch and format values are known."""
    issues: list[str] = []
    if cfg.arch not in _KNOWN_ARCHES:
        issues.append(f"Unknown arch '{cfg.arch}' (known: {', '.join(sorted(_KNOWN_ARCHES))})")
    if cfg.binary_format not in _KNOWN_FORMATS:
        issues.append(
            f"Unknown format '{cfg.binary_format}' (known: {', '.join(sorted(_KNOWN_FORMATS))})"
        )

    if issues:
        return CheckResult(
            name="Arch / Format",
            status=_WARN,
            message="; ".join(issues),
            fix="Update 'arch' and 'format' in rebrew-project.toml to supported values.",
        )
    return CheckResult(
        name="Arch / Format",
        status=_PASS,
        message=f"arch={cfg.arch}, format={cfg.binary_format}",
    )


def check_compiler(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler command is executable."""
    # 16-bit NE targets have no compile profile yet (ADR-001) — a 32-bit
    # CL.EXE cannot build them, so a missing toolchain is expected, not a
    # project defect.  Downgrade to a warning instead of a hard failure.
    if getattr(cfg, "arch", "") == "x86_16":
        return CheckResult(
            name="Compiler",
            status=_WARN,
            message="16-bit NE target — no 16-bit compile profile exists yet (ADR-001); "
            "byte matching is future work",
            fix="Analysis/documentation work as normal; matching needs a future "
            "16-bit compiler profile.",
        )

    cmd_str = cfg.compiler_command
    if not cmd_str:
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message="No compiler command configured",
            fix="Set [compiler] command in rebrew-project.toml (e.g. 'wine CL.EXE').",
        )

    try:
        parts = shlex.split(cmd_str)
    except ValueError:
        parts = cmd_str.split()

    # Check if the first token (e.g. "wine"/"wibo") is available
    exe = parts[0] if parts else ""
    exe_path = shutil.which(exe)
    is_wibo_runner = Path(exe).name == "wibo"
    if exe_path is None and exe != "wine" and not is_wibo_runner:
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message=f"Executable '{exe}' not found in PATH",
            fix=f"Install '{exe}' or update compiler.command in rebrew-project.toml.",
        )

    if is_wibo_runner and exe_path is None:
        # `init --install-wibo` writes a relative runner like tools/wibo —
        # resolve it against the project root, not PATH.
        local = Path(exe) if Path(exe).is_absolute() else cfg.root / Path(exe)
        if local.exists():
            exe_path = str(local)
        else:
            from rebrew.wibo import find_wibo

            found = find_wibo(cfg.root)
            if found is None:
                return CheckResult(
                    name="Compiler",
                    status=_WARN,
                    message="wibo runner not found",
                    fix=(
                        "Run 'rebrew init --install-wibo' or set compiler.command "
                        "to the wibo binary path."
                    ),
                )
            exe_path = str(found)

    # For Wine/wibo-based compilers, check the CL.EXE path.
    if exe == "wine":
        wine_path = shutil.which("wine")
        if wine_path is None:
            return CheckResult(
                name="Compiler",
                status=_FAIL,
                message="Wine is not installed or not in PATH",
                fix="Install Wine: apt install wine-stable (Debian/Ubuntu) or brew install wine.",
            )

    if exe == "wine" or is_wibo_runner:
        if len(parts) > 1:
            cl_path = Path(parts[1])
            if not cl_path.is_absolute():
                cl_path = cfg.root / cl_path
            if not cl_path.exists():
                fix_msg = "Place MSVC toolchain at the configured path or update compiler.command."
                cl_path_str = str(cl_path).lower()
                # Order matters: "msvc6.3"/"msvc6.6" also contain "msvc6".
                if "msvc6.3" in cl_path_str:
                    fix_msg += (
                        " Download: https://github.com/OmniBlade/decomp.me/"
                        "releases/download/msvcwin9x/msvc6.3.tar.gz"
                    )
                elif "msvc6.6" in cl_path_str:
                    fix_msg += (
                        " Download: https://github.com/OmniBlade/decomp.me/"
                        "releases/download/msvcwin9x/msvc6.6.tar.gz"
                    )
                elif "msvc7" in cl_path_str:
                    fix_msg += (
                        " Download: https://github.com/OmniBlade/decomp.me/"
                        "releases/download/msvcwin9x/msvc7.0.tar.gz"
                    )
                elif "msvc500" in cl_path_str or "msvc5" in cl_path_str:
                    fix_msg += (
                        " Download: https://codeload.github.com/archaic-msvc/"
                        "msvc500/tar.gz/refs/heads/master"
                    )
                elif "msvc6" in cl_path_str:
                    fix_msg += " Download: https://github.com/itsmattkc/MSVC600"
                elif "msvc400" in cl_path_str:
                    fix_msg += " Download: https://github.com/itsmattkc/MSVC400"
                elif "msvc420" in cl_path_str:
                    fix_msg += " Download: https://github.com/itsmattkc/MSVC420"
                elif "wcc" in cl_path_str or "watcom" in cl_path_str:
                    fix_msg += (
                        " Download (Watcom C/C++): https://github.com/OmniBlade/"
                        "decomp.me/releases/download/wcc10.5/wcc11.0.tar.gz"
                    )

                return CheckResult(
                    name="Compiler",
                    status=_FAIL,
                    message=f"CL.EXE not found at: {cl_path}",
                    fix=fix_msg,
                )

            # Quick smoke test: try running cl.exe with no args.  Use the
            # RESOLVED runner path (exe_path) — a relative tools/wibo would be
            # resolved against the process CWD, not cfg.root, and fail from a
            # subdirectory.
            runner_token = exe_path if exe_path else ("wine" if exe == "wine" else exe)
            display_runner = "wibo" if is_wibo_runner else "Wine"
            try:
                subprocess.run(
                    [runner_token, str(cl_path)],
                    capture_output=True,
                    timeout=10,
                    env={**os.environ, "WINEDEBUG": "-all"},
                )
                return CheckResult(
                    name="Compiler",
                    status=_PASS,
                    message=f"{display_runner} + {cl_path.name} (reachable)",
                )
            except subprocess.TimeoutExpired:
                return CheckResult(
                    name="Compiler",
                    status=_WARN,
                    message=f"{display_runner} + {cl_path.name} (timed out on smoke test)",
                    fix="The runner may be slow to start. This is usually fine for actual compilation.",
                )
            except (FileNotFoundError, OSError) as e:
                return CheckResult(
                    name="Compiler",
                    status=_FAIL,
                    message=f"Failed to invoke {display_runner}: {e}",
                    fix="Check the runner installation and CL.EXE path.",
                )
        if exe == "wine":
            return CheckResult(
                name="Compiler",
                status=_WARN,
                message=f"Wine found at {wine_path}, but no CL.EXE path specified in compiler.command",
                fix="Set compiler.command to 'wine /path/to/CL.EXE' in rebrew-project.toml.",
            )
        return CheckResult(
            name="Compiler",
            status=_WARN,
            message="wibo runner configured, but no CL.EXE path specified in compiler.command",
            fix="Set compiler.command to 'wibo /path/to/CL.EXE' in rebrew-project.toml.",
        )

    return CheckResult(
        name="Compiler",
        status=_PASS,
        message=f"Found: {exe_path or exe}",
    )


def check_toolchain_alignment(cfg: ProjectConfig) -> CheckResult:
    """Check that the configured compiler profile aligns with the binary.

    Uses the layered toolchain detector (DIE -> PDB -> heuristics) to guess
    what actually built the target and compares it against the configured
    ``[compiler] profile``.  A mismatch means byte-matching is impossible —
    the user should switch profiles or document blockers.
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return CheckResult(name="Toolchain alignment", status=_SKIP, message="binary not available")

    from rebrew.toolchain_detect import detect_toolchain, profile_matches_detection

    try:
        info = detect_toolchain(binary)
    except Exception:
        return CheckResult(name="Toolchain alignment", status=_SKIP, message="detection failed")

    profile = getattr(cfg, "compiler_profile", "") or "msvc6"
    if info.family == "unknown":
        return CheckResult(
            name="Toolchain alignment",
            status=_SKIP,
            message="binary compiler family not identified",
        )

    aligned, explanation = profile_matches_detection(profile, info)
    detail = f"detected {info.family} ({info.version_hint or 'unknown version'})"
    if info.detected_by:
        detail += f" via {info.detected_by}"
    if any("diec not found" in e for e in info.evidence):
        detail += "; diec not found (add tools/diec or PATH diec for stronger detection)"
    if info.flags:
        detail += f"; PDB flags: {' '.join(info.flags)}"
    if aligned:
        if explanation:
            return CheckResult(
                name="Toolchain alignment", status=_WARN, message=detail, fix=explanation
            )
        return CheckResult(name="Toolchain alignment", status=_PASS, message=detail)
    # Families no rebrew compiler profile can ever match (e.g. Borland
    # Delphi) are a documented-blocker situation, not a broken project:
    # intake already marks their functions BLOCKER and analysis works.
    # Downgrade to a warning so `rebrew doctor` reports a healthy analysis
    # project instead of a misleading hard failure.
    if info.family == "delphi":
        return CheckResult(
            name="Toolchain alignment",
            status=_WARN,
            message=detail,
            fix=explanation
            or "Delphi functions are documented as blockers — analysis works, matching does not.",
        )
    return CheckResult(
        name="Toolchain alignment",
        status=_FAIL,
        message=detail,
        fix=explanation or "Switch the [compiler] profile to match the detected family.",
    )


def check_delphi16_toolchain(cfg: ProjectConfig) -> CheckResult:
    """For 16-bit NE targets, report the Delphi 1.0 compile-path readiness.

    The vendored DCC.EXE + RTM.EXE + dosbox can already compile 16-bit
    executables headless (``rebrew.delphi16.compile_ne``), though byte
    matching is not yet wired (ADR-001).  Skipped for non-16-bit targets.
    """
    if getattr(cfg, "arch", "") != "x86_16":
        return CheckResult(name="Delphi 1.0 toolchain", status=_SKIP, message="not a 16-bit target")

    from rebrew.delphi16 import Delphi16Error, _find_dcc

    try:
        dcc = _find_dcc()
    except Delphi16Error as exc:
        return CheckResult(
            name="Delphi 1.0 toolchain",
            status=_FAIL,
            message=str(exc),
            fix="Restore the vendored toolchain (DCC.EXE + DELPHI.DSL + "
            "DPMI16BI.OVL + RTM.EXE) under tools/DELPHI10.",
        )

    rtm = dcc.parent / "RTM.EXE"
    if not rtm.exists():
        return CheckResult(
            name="Delphi 1.0 toolchain",
            status=_WARN,
            message=f"{dcc.name} found but RTM.EXE missing — DCC (a DPMI app) "
            "silently fails without the DOS Runtime Manager",
            fix="Copy RTM.EXE next to DCC.EXE (tools/DELPHI10).",
        )
    if shutil.which("dosbox") is None:
        return CheckResult(
            name="Delphi 1.0 toolchain",
            status=_WARN,
            message=f"{dcc.parent.name} toolchain found but dosbox not in PATH",
            fix="Install dosbox (DCC is a DOS DPMI app and must run under DOSBox).",
        )
    return CheckResult(
        name="Delphi 1.0 toolchain",
        status=_PASS,
        message=f"{dcc.parent} + dosbox ready — 16-bit compile path works "
        "(matching not yet wired, ADR-001)",
    )


def check_toolchain_backed(cfg: ProjectConfig) -> CheckResult:
    """For profiles backed by the toolchain abstraction (watcom, msvc1.52),
    report how the toolchain resolves: vendored host binary present, or the
    docker image pulled.  Replaces the misleading "binary not in PATH" the
    generic compiler check would give (vendored compilers live under
    tools/, not PATH).  Skipped for other profiles."""
    profile = str(getattr(cfg, "compiler_profile", ""))
    if profile not in ("watcom", "msvc1.52"):
        return CheckResult(name="Toolchain", status=_SKIP, message="not a toolchain-backed profile")

    from rebrew.toolchain import ToolchainError, _image_present, get_toolchain

    try:
        spec = get_toolchain(profile)
    except ToolchainError as exc:
        return CheckResult(name="Toolchain", status=_FAIL, message=str(exc))

    host_ok = None
    if spec.host_path is not None:
        host = Path(spec.host_path)
        host_ok = (host / spec.binary).exists() or (host / spec.host_bin / spec.binary).exists()
    image_ok = _image_present(spec.image) if spec.image is not None else None

    ready = bool(host_ok) or bool(image_ok)
    bits = []
    if host_ok:
        bits.append(f"vendored {spec.host_path}")
    if image_ok:
        bits.append(f"image {spec.image} pulled")
    status = _PASS if ready else _WARN
    if not ready:
        status = _FAIL
    message = f"{profile}: {' + '.join(bits) if bits else 'no vendored binary and no image pulled'}"
    fix = (
        ""
        if ready
        else f"Run `rebrew toolchain pull {profile}` or vendor the toolchain under tools/."
    )
    return CheckResult(name="Toolchain", status=status, message=message, fix=fix)


def check_runner(cfg: ProjectConfig) -> CheckResult:
    """Check that the configured runner (wine/wibo) is available."""
    runner = str(getattr(cfg, "compiler_runner", "")).strip()
    if not runner:
        return CheckResult(
            name="Runner", status=_PASS, message="No runner configured (native compiler)"
        )

    if shutil.which(runner):
        return CheckResult(name="Runner", status=_PASS, message=f"{runner} found in PATH")

    # `init --install-wibo` writes a relative runner like tools/wibo — resolve
    # it against the project root (and fall back to the shared wibo cache).
    if Path(runner).name == "wibo":
        from rebrew.wibo import find_wibo

        local = Path(runner) if Path(runner).is_absolute() else cfg.root / Path(runner)
        if local.exists():
            return CheckResult(name="Runner", status=_PASS, message=f"wibo found at {local}")
        found = find_wibo(cfg.root)
        if found:
            return CheckResult(name="Runner", status=_PASS, message=f"wibo found at {found}")
        return CheckResult(
            name="Runner",
            status=_WARN,
            message="wibo not found",
            fix=(
                "Run 'rebrew init --install-wibo' or download manually from "
                "https://github.com/decompals/wibo"
            ),
        )

    if runner == "wine":
        return CheckResult(name="Runner", status=_PASS, message="Wine (checked by compiler check)")

    return CheckResult(name="Runner", status=_WARN, message=f"Unknown runner '{runner}'")


def check_includes(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler include directory exists."""
    # 16-bit NE targets have no compile profile (ADR-001) — the include path
    # is moot, same as the compiler check.
    if getattr(cfg, "arch", "") == "x86_16":
        return CheckResult(
            name="Include path",
            status=_WARN,
            message="16-bit NE target — no compile profile (ADR-001)",
            fix="Analysis/docs work fine; includes apply to future 16-bit matching.",
        )
    inc_path: Path = cfg.compiler_includes
    if not inc_path.exists():
        return CheckResult(
            name="Include path",
            status=_FAIL,
            message=f"Not found: {inc_path}",
            fix="Set compiler.includes in rebrew-project.toml to the MSVC include directory.",
        )
    # Count header files
    headers = list(inc_path.glob("*.h")) + list(inc_path.glob("*.H"))
    return CheckResult(
        name="Include path",
        status=_PASS,
        message=f"{inc_path} ({len(headers)} headers)",
    )


def check_libs(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler lib directory exists."""
    lib_path: Path = cfg.compiler_libs
    if not lib_path.exists():
        return CheckResult(
            name="Lib path",
            status=_WARN,
            message=f"Not found: {lib_path}",
            fix="Set compiler.libs in rebrew-project.toml if linking is required.",
        )
    libs = list(lib_path.glob("*.lib")) + list(lib_path.glob("*.LIB"))
    return CheckResult(
        name="Lib path",
        status=_PASS,
        message=f"{lib_path} ({len(libs)} libs)",
    )


def check_function_list(cfg: ProjectConfig) -> CheckResult:
    """Check that the function list file exists and has valid content."""
    func_list: Path = cfg.function_list
    if not func_list.exists():
        return CheckResult(
            name="Function list",
            status=_WARN,
            message=f"Not found: {func_list}",
            fix=(
                "Create the function list (e.g. 'r2 -qc \"afl\" binary > functions.txt' "
                "or 'rz -qc \"afl\" binary > functions.txt')."
            ),
        )

    try:
        lines = func_list.read_text(encoding="utf-8", errors="replace").splitlines()
        non_empty = [line for line in lines if line.strip()]
        return CheckResult(
            name="Function list",
            status=_PASS,
            message=f"{func_list.name} ({len(non_empty)} entries)",
        )
    except OSError as e:
        return CheckResult(
            name="Function list",
            status=_FAIL,
            message=f"Cannot read: {e}",
            fix="Check file permissions.",
        )


def check_source_files(cfg: ProjectConfig) -> CheckResult:
    """Check that at least one source file exists in reversed_dir."""
    reversed_dir: Path = cfg.reversed_dir
    if not reversed_dir.exists():
        return CheckResult(
            name="Source files",
            status=_WARN,
            message=f"Directory not found: {reversed_dir}",
            fix=f"Create the directory: mkdir -p {reversed_dir}",
        )

    from rebrew.cli import iter_sources

    sources = iter_sources(reversed_dir, cfg)
    if not sources:
        ext = getattr(cfg, "source_ext", ".c")
        return CheckResult(
            name="Source files",
            status=_WARN,
            message=f"No *{ext} files in {reversed_dir}",
            fix="Use 'rebrew skeleton 0xVA' to generate initial source files.",
        )

    return CheckResult(
        name="Source files",
        status=_PASS,
        message=f"{len(sources)} source file(s) in {reversed_dir}",
    )


def check_metadata_files(cfg: ProjectConfig) -> CheckResult:
    """Check that rebrew-function.toml and rebrew-data.toml exist in metadata_dir."""
    metadata_dir: Path = cfg.metadata_dir
    func_toml = metadata_dir / "rebrew-function.toml"
    data_toml = metadata_dir / "rebrew-data.toml"
    missing: list[str] = []
    if not func_toml.exists():
        missing.append("rebrew-function.toml")
    if not data_toml.exists():
        missing.append("rebrew-data.toml")

    if missing:
        return CheckResult(
            name="Metadata TOML",
            status=_WARN,
            message=f"Missing in {metadata_dir}: {', '.join(missing)}",
            fix=f"Create with: touch {' '.join(str(metadata_dir / f) for f in missing)}",
        )
    return CheckResult(
        name="Metadata TOML",
        status=_PASS,
        message=f"rebrew-function.toml + rebrew-data.toml in {metadata_dir}",
    )


def check_bin_dir(cfg: ProjectConfig) -> CheckResult:
    """Check that the output bin directory exists or can be created."""
    bin_dir: Path = cfg.bin_dir
    if bin_dir.exists():
        return CheckResult(
            name="Bin directory",
            status=_PASS,
            message=str(bin_dir),
        )
    # Not a failure — it will be created on first compile
    return CheckResult(
        name="Bin directory",
        status=_PASS,
        message=f"{bin_dir} (will be created on first compile)",
    )


# ---------------------------------------------------------------------------
# Main diagnostic runner
# ---------------------------------------------------------------------------


def run_doctor(target: str | None = None) -> DoctorReport:
    """Run all diagnostic checks and return a report."""
    report = DoctorReport()

    config_result, cfg = check_config_parse(target=target)
    report.checks.append(config_result)
    if cfg is None:
        report.target = target or "(unknown)"
        return report

    report.target = cfg.target_name

    report.checks.append(check_target_binary(cfg))
    report.checks.append(check_arch_format(cfg))
    report.checks.append(check_toolchain_alignment(cfg))
    report.checks.append(check_delphi16_toolchain(cfg))
    report.checks.append(check_toolchain_backed(cfg))
    report.checks.append(check_compiler(cfg))
    report.checks.append(check_runner(cfg))
    report.checks.append(check_includes(cfg))
    report.checks.append(check_libs(cfg))
    report.checks.append(check_function_list(cfg))
    report.checks.append(check_source_files(cfg))
    report.checks.append(check_bin_dir(cfg))
    report.checks.append(check_metadata_files(cfg))
    report.checks.append(check_optional_tools(cfg))
    report.checks.append(check_flirt_sigs(cfg))
    report.checks.append(check_ghidra_sync(cfg))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Example:[/bold]\n\n"
    "  rebrew doctor · · · · · · · · · Check default target\n\n"
    "  rebrew doctor --target mygame · · Check specific target\n\n"
    "  rebrew doctor --json · · · · · · Machine-readable output\n\n"
    "[dim]Validates: rebrew-project.toml, target binary, compiler toolchain, include/lib "
    "paths, function list, and source directory.[/dim]"
)

_STATUS_ICONS = {
    _PASS: "\u2705",
    _FAIL: "\u274c",
    _WARN: "\u26a0\ufe0f",
    _SKIP: "\u23ed\ufe0f",
}

_STATUS_STYLES = {
    _PASS: "green",
    _FAIL: "red",
    _WARN: "yellow",
    _SKIP: "dim",
}

app = typer.Typer(
    help="Diagnostic checks for rebrew project health.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    install_wibo: bool = typer.Option(
        False,
        "--install-wibo",
        help="Download wibo to tools/wibo if missing; no-op if already installed.",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Run diagnostic checks on the rebrew project."""
    if install_wibo:
        from rebrew.wibo import download_wibo

        cfg = require_config(target=target, json_mode=json_output)
        wibo_path = cfg.root / "tools" / "wibo"
        tag_name = download_wibo(wibo_path)
        console.print(f"Downloaded wibo {tag_name} to {wibo_path}")

        toml_path = cfg.root / "rebrew-project.toml"
        if toml_path.exists():
            import re

            from rebrew.utils import atomic_write_text

            content = toml_path.read_text(encoding="utf-8")
            new_content = re.sub(
                r'(?m)^(\s*runner\s*=\s*)"[^"]*"',
                r'\1"tools/wibo"',
                content,
            )
            if new_content == content:
                new_content = re.sub(
                    r"(?m)^(\[compiler\]\s*\n)",
                    r'\1runner = "tools/wibo"\n',
                    content,
                )
            if new_content != content:
                atomic_write_text(toml_path, new_content, encoding="utf-8")
                console.print("Auto-enabled wibo in rebrew-project.toml")

    report = run_doctor(target=target)

    if json_output:
        json_print(report.to_dict())
    else:
        table = Table(show_header=True, header_style="bold", pad_edge=False)
        table.add_column("", width=2)
        table.add_column("Check", width=20)
        table.add_column("Message", no_wrap=False)
        table.add_column("Fix", no_wrap=False, style="dim")

        for check in report.checks:
            icon = _STATUS_ICONS.get(check.status, "?")
            style = _STATUS_STYLES.get(check.status, "")
            table.add_row(
                icon,
                f"[{style}]{check.name}[/{style}]",
                f"[{style}]{check.message}[/{style}]",
                check.fix or "",
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
        console.print(panel)

        if report.passed:
            console.print("[green]  Project looks healthy![/green]")
        else:
            console.print("[red]  Issues found. Fix the failures above and re-run.[/red]")

    if not report.passed:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()


def check_optional_tools(cfg: ProjectConfig) -> CheckResult:
    """Check availability of optional symbolic-proving tools (angr + claripy).

    ``rebrew prove`` needs both; a half-installed pair (angr without claripy,
    or claripy without angr) crashes at runtime with a confusing traceback.
    """
    from rebrew.cli import angr_available

    has_angr = angr_available()
    claripy_available = False
    import contextlib

    with contextlib.suppress(ImportError):
        import claripy  # noqa: F401

        claripy_available = True

    if has_angr and claripy_available:
        return CheckResult(
            name="Optional tools",
            status=_PASS,
            message="angr + claripy available (for 'rebrew prove')",
        )
    if has_angr:
        return CheckResult(
            name="Optional tools",
            status=_WARN,
            message="angr installed but claripy is missing — prove will crash",
            fix="Install the pair: 'uv add --dev angr' (pulls claripy).",
        )
    if claripy_available:
        return CheckResult(
            name="Optional tools",
            status=_WARN,
            message="claripy installed but angr is missing — prove needs both",
            fix="Install the pair: 'uv add --dev angr'.",
        )
    return CheckResult(
        name="Optional tools",
        status=_WARN,
        message="angr + claripy missing (for 'rebrew prove')",
        fix="Optional: 'uv add --dev angr' for symbolic proving.",
    )


def check_flirt_sigs(cfg: ProjectConfig) -> CheckResult:
    """Check the ``flirt_sigs/`` directory: present, non-empty, and every
    ``.pat``/``.sig`` file actually parses via python-flirt — the exact reader
    ``rebrew flirt`` uses.

    A directory full of corrupt or legacy signatures silently yields zero
    matches; this check surfaces that before the user wastes a scan.
    """
    sig_dir = cfg.root / "flirt_sigs"
    if not sig_dir.exists():
        return CheckResult(
            name="FLIRT signatures",
            status=_WARN,
            message="flirt_sigs/ directory not found",
            fix=(
                "Generate signatures from a compiler .lib with "
                "'rebrew gen-flirt-pat /path/to/msvcrt.lib "
                "--output flirt_sigs/msvcrt_vc6.pat', or copy .sig files "
                "(e.g. from fireeye/siglib) into flirt_sigs/."
            ),
        )

    sig_files = sorted(sig_dir.glob("*.pat")) + sorted(sig_dir.glob("*.sig"))
    if not sig_files:
        return CheckResult(
            name="FLIRT signatures",
            status=_WARN,
            message="flirt_sigs/ exists but contains no .pat/.sig files",
            fix="Add signatures as described above.",
        )

    try:
        import flirt  # noqa: F401
    except ImportError:
        return CheckResult(
            name="FLIRT signatures",
            status=_SKIP,
            message=f"{len(sig_files)} sig file(s) found, but python-flirt is not installed",
            fix="Install python-flirt to use 'rebrew flirt': 'uv add python-flirt'.",
        )

    total = 0
    problems: list[str] = []
    for filepath in sig_files:
        try:
            content = filepath.read_bytes()
            if filepath.suffix == ".sig":
                parsed = flirt.parse_sig(content)
            else:
                parsed = flirt.parse_pat(content.decode("utf-8", errors="ignore"))
            total += len(parsed)
            if not parsed:
                problems.append(f"{filepath.name} (0 signatures)")
        except (OSError, ValueError, TypeError, UnicodeDecodeError) as e:
            problems.append(f"{filepath.name} (corrupt: {e})")

    if problems:
        return CheckResult(
            name="FLIRT signatures",
            status=_WARN,
            message=f"{len(sig_files)} file(s), {total} sigs load; {len(problems)} problem file(s)",
            fix="Regenerate corrupt .pat files with 'rebrew gen-flirt-pat': " + "; ".join(problems),
        )
    return CheckResult(
        name="FLIRT signatures",
        status=_PASS,
        message=f"{len(sig_files)} file(s), {total} signatures load",
    )


def check_ghidra_sync(cfg: ProjectConfig) -> CheckResult:
    """Check the Ghidra sync setup: backend config, program path, and (for
    the ghidra-cli backend) the binary's presence."""
    backend = getattr(cfg, "ghidra_backend", "reva")
    program_path = getattr(cfg, "ghidra_program_path", "")

    if backend == "cli":
        from rebrew.ghidra.cli_backend import resolve_ghidra_cli

        found = resolve_ghidra_cli(cfg)
        if found is None:
            return CheckResult(
                name="Ghidra sync",
                status=_WARN,
                message="ghidra_backend = 'cli' but no ghidra-cli binary found",
                fix=(
                    "Install ghidra-cli (cargo install ghidra-cli) or place the "
                    "binary at tools/ghidra-cli."
                ),
            )
        if not program_path:
            return CheckResult(
                name="Ghidra sync",
                status=_WARN,
                message=f"ghidra-cli found ({found}), but ghidra_program_path is not set",
                fix="Set targets.<name>.ghidra_program_path in rebrew-project.toml.",
            )
        return CheckResult(
            name="Ghidra sync",
            status=_PASS,
            message=f"ghidra-cli backend ready ({found})",
        )

    # ReVa (MCP) backend.
    if not program_path:
        return CheckResult(
            name="Ghidra sync",
            status=_WARN,
            message="ghidra_program_path is not set — sync may target the wrong program",
            fix="Set targets.<name>.ghidra_program_path in rebrew-project.toml.",
        )
    return CheckResult(
        name="Ghidra sync",
        status=_PASS,
        message=f"ReVa backend ready (program: {program_path})",
    )
