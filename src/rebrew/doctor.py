"""doctor.py – Diagnostic command for rebrew project health.

Environment/setup health only (does not inspect the decompiled corpus):
config file, target binary, arch/format, toolchain alignment, compiler
image/executable, runner, include/lib paths, function-list existence,
source-dir existence, metadata-file existence, and integration tooling
(angr, FLIRT, Ghidra).  Source-corpus checks — annotation markers,
metadata placement, VA-vs-function-list consistency, and per-function
settings like cflags redundancy — live in ``rebrew lint``.  Doctor answers
"can this project work?", not "is the decompiled corpus internally
consistent?".

Usage::

    rebrew doctor
    rebrew doctor --target client_exe
    rebrew doctor --json
"""

import logging
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
logger = logging.getLogger(__name__)

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

_KNOWN_FORMATS = {"pe", "elf", "macho", "ne"}
_KNOWN_ARCHES = {"x86_16", "x86_32", "x86_64", "arm32", "arm64"}


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


def _toolchain_download_hint(path_str: str) -> str:
    """A download URL for a missing vendored toolchain, keyed by path.

    Matches the nested ``toolchain/<family>/<version>-<arch>`` layout and the
    legacy names (old projects may still reference pre-restructure dirs).
    Order matters: the SP mirrors contain ``msvc/6.0`` and the legacy
    ``msvc6.3``/``msvc6.6`` contain bare ``msvc6``.  Returns the hint text
    (with the leading space) or "" when unknown.
    """
    if "6.0-sp3-win32" in path_str or "msvc6.3" in path_str:
        return (
            " Download: https://github.com/OmniBlade/decomp.me/"
            "releases/download/msvcwin9x/msvc-6.0-sp3-win32.tar.gz"
        )
    if "6.0-sp6-win32" in path_str or "msvc6.6" in path_str:
        return (
            " Download: https://github.com/OmniBlade/decomp.me/"
            "releases/download/msvcwin9x/msvc-6.0-sp6-win32.tar.gz"
        )
    if "7.0-win32" in path_str or "msvc7" in path_str:
        return (
            " Download: https://github.com/OmniBlade/decomp.me/"
            "releases/download/msvcwin9x/msvc-7.0-win32.tar.gz"
        )
    if "5.0-win32" in path_str or "msvc500" in path_str or "msvc5" in path_str:
        return (
            " Download: https://codeload.github.com/archaic-msvc/msvc500/tar.gz/refs/heads/master"
        )
    if "6.0-win32" in path_str or "msvc6" in path_str:
        return " Download: https://github.com/itsmattkc/msvc-6.0-win32"
    if "4.0-win32" in path_str or "msvc400" in path_str:
        return " Download: https://codeload.github.com/itsmattkc/MSVC400/tar.gz/refs/heads/master"
    if "4.2-win32" in path_str or "msvc420" in path_str:
        # The vendored 4.2 tree comes from the archaic-msvc repo (its own
        # README + the pinned ToolchainSource); the itsmattkc mirror is a
        # different, older snapshot.
        return (
            " Download: https://codeload.github.com/archaic-msvc/msvc420/tar.gz/refs/heads/master"
        )
    if "wcc" in path_str or "watcom" in path_str:
        return (
            " Download (Watcom C/C++): https://github.com/OmniBlade/"
            "decomp.me/releases/download/wcc10.5/wcc11.0.tar.gz"
        )
    if "1.52-win16" in path_str or "msvc152" in path_str:
        return " Download (MSVC 1.52): https://archive.org/details/en_vc152_202512"
    return ""


def check_compiler(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler command is executable."""
    # A 16-bit target needs a 16-bit-capable profile (msvc1.52 DOSBox
    # CL.EXE, tc16 DOSBox TCC.EXE, watcom16 native wcc).  With one
    # configured, proceed to the normal executable check; otherwise a
    # 32-bit compiler cannot build the target, so a missing toolchain is
    # expected, not a project defect.  Downgrade to a warning instead of a
    # hard failure, and suggest the right profile via the detector.
    _16BIT = {"msvc1.52", "tc16", "tc20", "watcom16"}
    if getattr(cfg, "arch", "") == "x86_16" and getattr(cfg, "compiler_profile", "") not in _16BIT:
        hint = "msvc1.52, tc16, tc20, or watcom16"
        try:
            from rebrew.toolchain_detect import detect_toolchain, suggest_profile

            info = detect_toolchain(cfg.target_binary)
            guess = suggest_profile(info, cfg.target_binary)
            if guess:
                hint = guess
        except (OSError, ValueError, ImportError, AttributeError):
            logger.debug("profile suggestion failed", exc_info=True)  # best-effort recommendation
        return CheckResult(
            name="Compiler",
            status=_WARN,
            message="16-bit target — configure a 16-bit compiler profile for "
            f"byte matching (e.g. '{hint}')",
            fix=f'Set compiler.profile = "{hint}"; analysis/docs work either way.',
        )

    # Docker-only execution: every Windows/DOS profile compiles through its
    # docker image — the image IS the compiler.  Only native-Linux profiles
    # (gcc-pe and friends) fall through to the legacy executable check.
    from rebrew.toolchain import TOOLCHAINS, image_present

    _profile = str(getattr(cfg, "compiler_profile", ""))
    _spec = TOOLCHAINS.get(_profile) if _profile else None
    if _spec is not None and _spec.image is not None:
        if image_present(_spec.image):
            return CheckResult(
                name="Compiler",
                status=_PASS,
                message=f"{_profile} docker image {_spec.image} ready",
            )
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message=f"{_profile} docker image {_spec.image} not built",
            fix=f"Run `rebrew toolchain build {_profile}` (docker-only execution).",
        )
    if _spec is not None and _spec.runtime != "native":
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message=f"{_profile} has no docker image — execution is docker-only",
            fix=f"Run `rebrew toolchain build {_profile}` first.",
        )

    cmd_str = cfg.compiler_command
    if not cmd_str:
        return CheckResult(
            name="Compiler",
            status=_FAIL,
            message="No compiler command configured",
            fix="Set [compiler] profile to a docker-backed toolchain, or command for a native compiler.",
        )

    try:
        parts = shlex.split(cmd_str)
    except ValueError:
        parts = cmd_str.split()

    # Check if the first token (e.g. "wine"/"wibo") is available
    exe = parts[0] if parts else ""
    exe_path = shutil.which(exe)
    is_wibo_runner = Path(exe).name == "wibo"
    # A relative command (e.g. toolchain/msvc/1.52-win16/BIN/CL.EXE) resolves against the
    # project root — do not require it on PATH (msvc1.52's direct DOSBox
    # command, watcom, gcc-pe vendored paths).
    if exe_path is None and exe != "wine" and not is_wibo_runner:
        local_exe = Path(exe) if Path(exe).is_absolute() else cfg.root / Path(exe)
        if local_exe.exists():
            exe_path = str(local_exe)
        else:
            # Same install-tools fallback resolve_cl_command uses — a wibo
            # config has no runner prefix, so exe is the CL.EXE path.
            from rebrew.utils import find_install_tool

            alt = find_install_tool(exe)
            if alt is not None:
                exe_path = str(alt)
            else:
                hint = _toolchain_download_hint(str(exe).lower())
                return CheckResult(
                    name="Compiler",
                    status=_FAIL,
                    message=f"Executable '{exe}' not found in PATH or project",
                    fix=(
                        f"Install '{exe}' or update compiler.command in rebrew-project.toml.{hint}"
                    ),
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
                # Project-local tools/ absent?  Fall back to the rebrew
                # install's own vendored tree — resolve_cl_command does the
                # same, so a missing symlink is NOT a broken compiler.
                from rebrew.utils import find_install_tool

                alt = find_install_tool(parts[1])
                if alt is not None:
                    cl_path = alt
                else:
                    fix_msg = (
                        "Place MSVC toolchain at the configured path or update compiler.command."
                        + _toolchain_download_hint(str(cl_path).lower())
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
                from rebrew.compile import maybe_headless_wine

                smoke_cmd, smoke_env = maybe_headless_wine(
                    [runner_token, str(cl_path)],
                    {**os.environ, "WINEDEBUG": "-all"},
                )
                subprocess.run(
                    smoke_cmd,
                    capture_output=True,
                    timeout=10,
                    env=smoke_env,
                )
                note = ""
                if exe == "wine":
                    if shutil.which("Xvfb") is not None:
                        note = " — headless (Xvfb)"
                    else:
                        note = (
                            " — a virtual-desktop window may pop; install xvfb "
                            "for headless, or use wibo (rebrew init --install-wibo)"
                        )
                return CheckResult(
                    name="Compiler",
                    status=_PASS,
                    message=f"{display_runner} + {cl_path.name} (reachable){note}",
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
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(
            name="Toolchain alignment", status=_SKIP, message=f"detection failed: {exc}"
        )

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
        from rebrew.toolchain_detect import backend_display_name

        detail += f" via {backend_display_name(info.detected_by)}"
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

    The vendored DCC.EXE + RTM.EXE + dosbox can compile 16-bit NE
    executables headless (``rebrew.delphi16.compile_ne``); Delphi's
    Borland ABI has no matchable rebrew profile, so the toolchain is for
    research (compile + NE parse), and Delphi functions are documented as
    blockers.  Skipped for non-16-bit targets.
    """
    if getattr(cfg, "arch", "") != "x86_16":
        return CheckResult(name="Delphi 1.0 toolchain", status=_SKIP, message="not a 16-bit target")

    from rebrew.delphi16 import Delphi16Error, find_dcc

    try:
        dcc = find_dcc()
    except Delphi16Error as exc:
        return CheckResult(
            name="Delphi 1.0 toolchain",
            status=_FAIL,
            message=str(exc),
            fix="Restore the vendored toolchain (DCC.EXE + DELPHI.DSL + "
            "DPMI16BI.OVL + RTM.EXE) under rebrew-toolchains/delphi/1.0-win16/source.",
        )

    rtm = dcc.parent / "RTM.EXE"
    if not rtm.exists():
        return CheckResult(
            name="Delphi 1.0 toolchain",
            status=_WARN,
            message=f"{dcc.name} found but RTM.EXE missing — DCC (a DPMI app) "
            "silently fails without the DOS Runtime Manager",
            fix="Copy RTM.EXE next to DCC.EXE (rebrew-toolchains/delphi/1.0-win16/source).",
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
    """For docker-backed profiles, report the execution state: the docker
    image must be built (execution is docker-only — no host wine/dosbox
    fallback); the vendored tree is informational (it is the byte-identical
    source the image builds from).  Native-Linux profiles (gcc-pe, watcom16)
    skip (their binary is checked by the generic compiler check)."""
    profile = str(getattr(cfg, "compiler_profile", ""))
    from rebrew.toolchain import ToolchainError, get_toolchain, image_present

    try:
        spec = get_toolchain(profile)
    except ToolchainError:
        return CheckResult(name="Toolchain", status=_SKIP, message="not a toolchain-backed profile")
    if spec.image is None:
        return CheckResult(
            name="Toolchain", status=_SKIP, message="not a docker-backed profile (native binary)"
        )

    image_ok = image_present(spec.image)
    host_present = spec.host_path is not None and Path(spec.host_path).exists()
    bits = [f"image {spec.image} pulled"] if image_ok else []
    if host_present:
        bits.append(f"vendored tree {spec.host_path} present (build source)")
    ready = image_ok
    status = _PASS if ready else _FAIL
    message = f"{profile}: {' + '.join(bits) if bits else 'docker image not built'}"
    fix = "" if ready else f"Run `rebrew toolchain build {profile}` (docker-only execution)."
    return CheckResult(name="Toolchain", status=status, message=message, fix=fix)


def check_cache_backend(cfg: ProjectConfig) -> CheckResult:
    """The configured compile-cache backend must be a registered backend.

    An unknown ``[cache] backend`` only surfaces when the cache is opened
    (compile time); doctor reports it up front, before the first compile."""
    backend = str(getattr(cfg, "cache_backend", "diskcache"))
    from rebrew.compile_cache import available_cache_backends

    known = available_cache_backends()
    if backend in known:
        return CheckResult(
            name="Cache",
            status=_PASS,
            message=f"[cache] backend = {backend}",
            fix="",
        )
    return CheckResult(
        name="Cache",
        status=_FAIL,
        message=f"[cache] backend = {backend!r} is not a registered backend",
        fix=(
            f"Known backends: {', '.join(known)} — set [cache] backend in "
            "rebrew-project.toml or install the plugin that provides it"
        ),
    )


def check_runner(cfg: ProjectConfig) -> CheckResult:
    """Check the execution runner.  Docker-backed profiles run through
    their docker image (wine/wibo config is obsolete for them); native-Linux
    profiles need no runner."""
    from rebrew.toolchain import TOOLCHAINS

    _profile = str(getattr(cfg, "compiler_profile", ""))
    _spec = TOOLCHAINS.get(_profile) if _profile else None
    if _spec is not None and _spec.image is not None:
        from rebrew.toolchain import image_present

        if image_present(_spec.image):
            return CheckResult(
                name="Runner", status=_PASS, message=f"docker image {_spec.image} ready"
            )
        return CheckResult(
            name="Runner",
            status=_WARN,
            message=f"docker image {_spec.image} not built",
            fix=f"Run `rebrew toolchain build {_profile}`.",
        )

    runner = str(getattr(cfg, "compiler_runner", "")).strip()
    if not runner:
        return CheckResult(
            name="Runner", status=_PASS, message="No runner configured (native compiler)"
        )

    if Path(runner).name == "wibo":
        # `init --install-wibo` writes a relative runner like tools/wibo —
        # resolve it against the project root (and fall back to the shared
        # wibo cache / PATH).
        if shutil.which(runner):
            return CheckResult(name="Runner", status=_PASS, message=f"{runner} found in PATH")
        local = Path(runner) if Path(runner).is_absolute() else cfg.root / Path(runner)
        if local.exists():
            return CheckResult(name="Runner", status=_PASS, message=f"wibo found at {local}")
        from rebrew.wibo import find_wibo

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
        # Wine is the compatible default: the docker images run wine
        # (REBREW_RUNNER defaults to wine) and wibo — while faster and
        # headless — FAILS on some tools, so rebrew deliberately does not
        # recommend the switch.  A wibo binary sitting around is reported
        # as an informational note, never as a suggested change.
        from rebrew.wibo import find_wibo

        if shutil.which("wine") is not None and find_wibo(cfg.root) is not None:
            return CheckResult(
                name="Runner",
                status=_PASS,
                message=(
                    "Wine (checked by compiler check); wibo also available in "
                    "tools/ — wibo is faster but fails on some tools, wine "
                    "remains the default"
                ),
            )
        return CheckResult(name="Runner", status=_PASS, message="Wine (checked by compiler check)")

    if shutil.which(runner):
        return CheckResult(name="Runner", status=_PASS, message=f"{runner} found in PATH")

    return CheckResult(name="Runner", status=_WARN, message=f"Unknown runner '{runner}'")


def _docker_toolchain_check(cfg: ProjectConfig, name: str, what: str) -> CheckResult | None:
    """For docker-backed profiles, the image IS the include/lib provider.

    Execution is docker-only: the image encapsulates the compiler AND its
    include/lib trees (it is built from the vendored toolchain source), so a
    dangling host ``compiler.includes``/``compiler.libs`` path is not a
    first-run failure — it is only meaningful for legacy native/wine/wibo
    profiles.  Returns a CheckResult, or None when the profile is not
    docker-backed (the caller proceeds with the host-path check).
    """
    from rebrew.toolchain import TOOLCHAINS, image_present

    profile = str(getattr(cfg, "compiler_profile", ""))
    spec = TOOLCHAINS.get(profile) if profile else None
    if spec is None or spec.image is None:
        return None
    if image_present(spec.image):
        return CheckResult(
            name=name,
            status=_PASS,
            message=f"{profile}: {what} provided by docker image {spec.image}",
        )
    return CheckResult(
        name=name,
        status=_WARN,
        message=f"{profile}: docker image {spec.image} not built",
        fix=f"Run `rebrew toolchain build {profile}` (execution is docker-only).",
    )


def check_includes(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler include directory exists."""
    # A 16-bit NE target without the msvc1.52 profile has no usable compile
    # path — the include dir is moot, same as the compiler check.  With
    # msvc1.52 configured, the vendored msvc-1.52-win16/INCLUDE is staged into the
    # DOSBox sandbox as C:\INCLUDE, so the host path check still applies.
    if getattr(cfg, "arch", "") == "x86_16" and getattr(cfg, "compiler_profile", "") != "msvc1.52":
        return CheckResult(
            name="Include path",
            status=_WARN,
            message="16-bit NE target — configure msvc1.52 for includes",
            fix='Set compiler.profile = "msvc1.52" (vendored INCLUDE is '
            "staged as C:\\INCLUDE in the DOSBox sandbox).",
        )
    docker = _docker_toolchain_check(cfg, "Include path", "includes")
    if docker is not None:
        return docker
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
    docker = _docker_toolchain_check(cfg, "Lib path", "libs")
    if docker is not None:
        return docker
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

    from rebrew.sources import iter_sources

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
    """Check that rebrew-functions.toml and rebrew-data.toml exist in metadata_dir."""
    metadata_dir: Path = cfg.metadata_dir
    func_toml = metadata_dir / "rebrew-functions.toml"
    data_toml = metadata_dir / "rebrew-data.toml"
    missing: list[str] = []
    if not func_toml.exists():
        missing.append("rebrew-functions.toml")
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
        message=f"rebrew-functions.toml + rebrew-data.toml in {metadata_dir}",
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
    report.checks.append(check_cache_backend(cfg))
    # Project-level config vs binary fingerprints: CRT linkage + opt-level
    # are kept in doctor because they diagnose "you configured the wrong
    # toolchain shape" before any corpus exists.  Per-function metadata
    # checks (e.g. redundant cflags) live in `rebrew lint` (W029).
    report.checks.append(check_crt_linkage(cfg))
    report.checks.append(check_opt_level(cfg))
    if getattr(cfg, "arch", "") == "x86_16":
        # Delphi 1.0 is a 16-bit-only path — don't show a noise row on
        # 32-bit targets where it structurally cannot apply.
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
    "[dim]Validates: rebrew-project.toml, target binary, arch/format, compiler "
    "toolchain & runner, include/lib paths, function list, source dir, bin dir, "
    "and metadata files.  Per-function/corpus checks (markers, VAs, metadata "
    "fields, cflags redundancy) are `rebrew lint` instead.[/dim]"
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

        # Docker-backed profiles execute through their image, which runs
        # WINE by default (REBREW_RUNNER defaults to wine; wibo is opt-in and
        # fails on some tools).  The config runner is obsolete for them, so
        # --install-wibo must NOT rewrite runner = "tools/wibo" — that would
        # silently steer a docker-only project toward the less-compatible
        # runtime the user just reported failing.  Only legacy host-runner
        # profiles (native/wine/wibo without an image) get the rewrite.
        from rebrew.toolchain import TOOLCHAINS

        profile = str(getattr(cfg, "compiler_profile", ""))
        spec = TOOLCHAINS.get(profile) if profile else None
        if spec is not None and spec.image is not None:
            console.print(
                f"[yellow]note:[/yellow] {profile} is docker-backed — execution "
                f"runs through image {spec.image}, which uses wine by default; "
                "the runner config is obsolete and was left untouched (wibo "
                "is available in tools/ for legacy profiles)"
            )
            return

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
        import flirt
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
        from rebrew.ghidra import resolve_ghidra_cli

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
        return CheckResult(name="CRT linkage", status=_SKIP, message="binary not available")
    profile = getattr(cfg, "compiler_profile", "") or ""
    if not profile.startswith("msvc"):
        return CheckResult(name="CRT linkage", status=_SKIP, message="non-msvc profile")

    from rebrew.toolchain_detect import detect_toolchain

    try:
        info = detect_toolchain(binary)
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(name="CRT linkage", status=_SKIP, message=f"detection failed: {exc}")
    if not info.base_cflags:
        return CheckResult(name="CRT linkage", status=_SKIP, message="CRT linkage not identifiable")

    base_cflags = getattr(cfg, "base_cflags", "") or ""
    detected = info.base_cflags  # e.g. "/MD" or "/MT"
    if detected in base_cflags:
        return CheckResult(
            name="CRT linkage",
            status=_PASS,
            message=f"{info.crt} ({info.crt_linkage}) — base_cflags matches ({detected})",
        )
    return CheckResult(
        name="CRT linkage",
        status=_WARN,
        message=f"{info.crt} ({info.crt_linkage}) needs base_cflags {detected}, "
        f"project has '{base_cflags or '(unset)'}'",
        fix=f'Set base_cflags = "/nologo /c {detected}" in rebrew-project.toml',
    )


def check_opt_level(cfg: ProjectConfig) -> CheckResult:
    """Check the project's optimization flag against the binary's detected one.

    MSVC /O1 vs /O2 produce different argument-passing codegen for wrapper
    functions (push-[mem] + pop ecx vs load-first + add esp), so compiling
    with the wrong level silently breaks byte-matching at every wrapper call
    site.  The detection fingerprint (see toolchain_detect) reports the
    dominant level — or "mixed" when the binary was built with per-file /O
    overrides, in which case a project-wide flag cannot be right and the
    user should flag-sweep per function.
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return CheckResult(name="Optimization level", status=_SKIP, message="binary not available")
    profile = getattr(cfg, "compiler_profile", "") or ""
    if not profile.startswith("msvc"):
        return CheckResult(name="Optimization level", status=_SKIP, message="non-msvc profile")

    from rebrew.toolchain_detect import detect_toolchain

    try:
        info = detect_toolchain(binary)
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(
            name="Optimization level", status=_SKIP, message=f"detection failed: {exc}"
        )
    if not info.opt_level:
        return CheckResult(
            name="Optimization level",
            status=_SKIP,
            message="codegen fingerprint inconclusive (no wrapper-style evidence)",
        )

    cflags = getattr(cfg, "cflags", "") or ""
    if info.opt_level.startswith("mixed"):
        # Mixed build: no single project flag is right.  Only flag when the
        # project pins one level (a hint, not an error — the user may be
        # mid-sweep).
        if "/O1" in cflags or "/O2" in cflags:
            return CheckResult(
                name="Optimization level",
                status=_PASS,
                message=f"binary shows {info.opt_level} wrapper styles — project cflags "
                f"'{cflags}' can only match one half; use per-function flag sweeps",
                fix="rebrew match <file> --flag-sweep-only",
            )
        return CheckResult(
            name="Optimization level",
            status=_PASS,
            message=f"{info.opt_level} detected — project uses per-function flags",
        )

    detected = info.opt_level  # "/O1" or "/O2"
    if detected in cflags:
        return CheckResult(
            name="Optimization level",
            status=_PASS,
            message=f"binary fingerprint shows {detected} — cflags matches",
        )
    return CheckResult(
        name="Optimization level",
        status=_WARN,
        message=f"binary fingerprint shows {detected}, project cflags is '{cflags or '(unset)'}'",
        fix=f'Set compiler cflags to "{detected}" in rebrew-project.toml (or per-function metadata)',
    )
