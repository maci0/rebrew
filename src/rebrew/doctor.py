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

from rebrew.cli import TargetOption, get_config, json_print
from rebrew.config import ProjectConfig

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


def check_config_parse(
    root: Path | None, target: str | None
) -> tuple[CheckResult, ProjectConfig | None]:
    """Check that rebrew-project.toml exists and parses without errors."""
    try:
        cfg = get_config(target=target)
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
    except Exception as e:
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
    except Exception as e:
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

    # Check if the first token (e.g. "wine") is available
    exe = parts[0] if parts else ""
    exe_path = shutil.which(exe)
    if exe_path is None and exe != "wine":
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message=f"Executable '{exe}' not found in PATH",
            fix=f"Install '{exe}' or update compiler.command in rebrew-project.toml.",
        )

    # For Wine-based compilers, check the CL.EXE path
    if exe == "wine":
        wine_path = shutil.which("wine")
        if wine_path is None:
            return CheckResult(
                name="Compiler",
                status=_FAIL,
                message="Wine is not installed or not in PATH",
                fix="Install Wine: apt install wine-stable (Debian/Ubuntu) or brew install wine.",
            )

        if len(parts) > 1:
            cl_path = Path(parts[1])
            if not cl_path.is_absolute():
                cl_path = cfg.root / cl_path
            if not cl_path.exists():
                return CheckResult(
                    name="Compiler",
                    status=_FAIL,
                    message=f"CL.EXE not found at: {cl_path}",
                    fix="Place MSVC toolchain at the configured path or update compiler.command.",
                )

            # Quick smoke test: try running cl.exe with no args
            try:
                subprocess.run(
                    ["wine", str(cl_path)],
                    capture_output=True,
                    timeout=10,
                    env={**os.environ, "WINEDEBUG": "-all"},
                )
                return CheckResult(
                    name="Compiler",
                    status=_PASS,
                    message=f"Wine + {cl_path.name} (reachable)",
                )
            except subprocess.TimeoutExpired:
                return CheckResult(
                    name="Compiler",
                    status=_WARN,
                    message=f"Wine + {cl_path.name} (timed out on smoke test)",
                    fix="Wine may be slow to start. This is usually fine for actual compilation.",
                )
            except (FileNotFoundError, OSError) as e:
                return CheckResult(
                    name="Compiler",
                    status=_FAIL,
                    message=f"Failed to invoke Wine: {e}",
                    fix="Check Wine installation and CL.EXE path.",
                )
        return CheckResult(
            name="Compiler",
            status=_PASS,
            message=f"Wine found at {wine_path}",
        )

    return CheckResult(
        name="Compiler",
        status=_PASS,
        message=f"Found: {exe_path or exe}",
    )


def check_runner(cfg: ProjectConfig) -> CheckResult:
    """Check that the configured runner (wine/wibo) is available."""
    runner = str(getattr(cfg, "compiler_runner", "")).strip()
    if not runner:
        return CheckResult(
            name="Runner", status=_PASS, message="No runner configured (native compiler)"
        )

    if shutil.which(runner):
        return CheckResult(name="Runner", status=_PASS, message=f"{runner} found in PATH")

    if runner == "wibo":
        from rebrew.wibo import find_wibo

        found = find_wibo(cfg.root)
        if found:
            return CheckResult(name="Runner", status=_PASS, message=f"wibo found at {found}")
        return CheckResult(
            name="Runner",
            status=_WARN,
            message="wibo not found",
            fix=(
                "Run 'rebrew doctor --install-wibo' or download manually from "
                "https://github.com/decompals/wibo"
            ),
        )

    if runner == "wine":
        return CheckResult(name="Runner", status=_PASS, message="Wine (checked by compiler check)")

    return CheckResult(name="Runner", status=_WARN, message=f"Unknown runner '{runner}'")


def check_includes(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler include directory exists."""
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

    # 1. Config parse
    config_result, cfg = check_config_parse(root=None, target=target)
    report.checks.append(config_result)
    if cfg is None:
        report.target = target or "(unknown)"
        return report

    report.target = cfg.target_name

    # 2. Target binary
    report.checks.append(check_target_binary(cfg))

    # 3. Arch / Format
    report.checks.append(check_arch_format(cfg))

    # 4. Compiler
    report.checks.append(check_compiler(cfg))

    # 4b. Runner
    report.checks.append(check_runner(cfg))

    # 5. Include path
    report.checks.append(check_includes(cfg))

    # 6. Lib path
    report.checks.append(check_libs(cfg))

    # 7. Function list
    report.checks.append(check_function_list(cfg))

    # 8. Source files
    report.checks.append(check_source_files(cfg))

    # 9. Bin directory
    report.checks.append(check_bin_dir(cfg))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = """\
[bold]Example:[/bold]

rebrew doctor                    Check default target

rebrew doctor --target lego1     Check specific target

rebrew doctor --json             Machine-readable output

[dim]Validates: rebrew-project.toml, target binary, compiler toolchain, include/lib
paths, function list, and source directory.[/dim]"""

_STATUS_ICONS = {
    _PASS: "\u2705",
    _FAIL: "\u274c",
    _WARN: "\u26a0\ufe0f",
    _SKIP: "\u23ed\ufe0f",
}

app = typer.Typer(
    help="Diagnostic checks for rebrew project health.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    target: str | None = TargetOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    install_wibo: bool = typer.Option(False, "--install-wibo", help="Download wibo to tools/wibo"),
) -> None:
    """Run diagnostic checks on the rebrew project."""
    if install_wibo:
        from rebrew.wibo import download_wibo

        cfg = get_config(target=target)
        wibo_path = cfg.root / "tools" / "wibo"
        tag_name = download_wibo(wibo_path)
        print(f"Downloaded wibo {tag_name} to {wibo_path}")

    report = run_doctor(target=target)

    if json_output:
        json_print(report.to_dict())
    else:
        print(f"\nRebrew Doctor — target: {report.target}")
        print("=" * 60)

        for check in report.checks:
            icon = _STATUS_ICONS.get(check.status, "?")
            print(f"  {icon}  {check.name}: {check.message}")
            if check.fix:
                print(f"       Fix: {check.fix}")

        print("=" * 60)
        parts = []
        if report.pass_count:
            parts.append(f"{report.pass_count} passed")
        if report.fail_count:
            parts.append(f"{report.fail_count} failed")
        if report.warn_count:
            parts.append(f"{report.warn_count} warnings")
        print(f"  {', '.join(parts)}")

        if report.passed:
            print("\n  Project looks healthy!\n")
        else:
            print("\n  Issues found. Fix the failures above and re-run.\n")

    if not report.passed:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
