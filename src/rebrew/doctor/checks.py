"""Core project, binary, toolchain, runner, source, and metadata doctor checks."""

import logging
from dataclasses import dataclass, field
lazy import os
lazy import shlex
lazy import shutil
lazy import subprocess
lazy import sys
lazy from pathlib import Path
lazy from typing import Any

from rebrew.config import (
    ARCH_PRESETS,
    KNOWN_FORMATS,
    ProjectConfig,
    compiler_dir,
    inventory_path_for,
    load_config,
)
from rebrew.errors import RebrewError
lazy from rebrew.metadata.storage import metadata_store

logger = logging.getLogger(__name__)

#: Status labels a CheckResult carries.  ``OK`` is spelled without "pass"
#: so ruff S105 (hardcoded credential) stays on for the tree.
OK = "pass"
FAIL = "fail"
WARN = "warn"
SKIP = "skip"

# The vocabulary is owned by rebrew.config, which already rejects a value
# outside it at load.  A private copy here could only ever agree or disagree
# with the loader, and a newly added arch or format would leave this check
# reporting a value the loader accepts.
KNOWN_ARCHES = set(ARCH_PRESETS)

#: Our preservation copies of third-party toolchain media (archaic-toolchains org), the same
#: release the pinned ToolchainSource URLs use.
_MIRROR = "https://github.com/archaic-toolchains/{repo}/releases/download/2026-11-10/{asset}"

#: The most disagreeing record keys :func:`check_function_bindings` names in its message.
_BINDING_CONFLICTS_SHOWN = 10


def resolve_pkg_hook[T](attr: str, local_val: T, default_val: T) -> T:
    """Return *local_val* if patched locally, else any override on ``rebrew.doctor``."""
    if local_val is not default_val:
        return local_val
    pkg = sys.modules.get("rebrew.doctor")
    if pkg is not None:
        pkg_val: T = getattr(pkg, attr, default_val)
        if pkg_val is not default_val:
            return pkg_val
    return local_val


# ---------------------------------------------------------------------------
# Report models and errors
# ---------------------------------------------------------------------------


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
        return all(c.status != FAIL for c in self.checks)

    @property
    def pass_count(self) -> int:
        """Number of checks that passed."""
        return sum(1 for c in self.checks if c.status == OK)

    @property
    def fail_count(self) -> int:
        """Number of checks that failed."""
        return sum(1 for c in self.checks if c.status == FAIL)

    @property
    def warn_count(self) -> int:
        """Number of checks with warnings."""
        return sum(1 for c in self.checks if c.status == WARN)

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


class LibIndexUnavailable(RebrewError, RuntimeError):
    """The stock LIBCMT archive is present but its bytes could not be read.

    Carries the shared :class:`~rebrew.errors.RebrewError` base so a
    consumer's documented ``except RebrewError`` handler catches an
    unreadable archive like any other rebrew failure.
    """


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


_DEFAULT_LOAD_CONFIG = load_config


def check_config_parse(target: str | None) -> tuple[CheckResult, ProjectConfig | None]:
    """Check that rebrew-project.toml exists and parses without errors."""
    loader = resolve_pkg_hook("load_config", load_config, _DEFAULT_LOAD_CONFIG)
    try:
        cfg = loader(target=target)
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=OK,
                message=f"Parsed successfully (target: {cfg.target_name})",
            ),
            cfg,
        )
    except FileNotFoundError as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=FAIL,
                message=str(e),
                fix="Run 'rebrew init' to create a new project, or cd into a project directory.",
            ),
            None,
        )
    except KeyError as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=FAIL,
                message=f"Config error: {e}",
                fix="Check rebrew-project.toml for missing [targets] section or invalid target name.",
            ),
            None,
        )
    except (ValueError, TypeError, OSError) as e:
        return (
            CheckResult(
                name="rebrew-project.toml",
                status=FAIL,
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
            status=FAIL,
            message=f"Not found: {bin_path}",
            fix=f"Place the target binary at '{bin_path}' or update 'binary' in rebrew-project.toml.",
        )

    try:
        from rebrew.formats.binary_loader import load_binary

        info = load_binary(bin_path, fmt=cfg.binary_format)
        sections = len(info.sections)
        return CheckResult(
            name="Target binary",
            status=OK,
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
            status=FAIL,
            message=f"Failed to load: {e}",
            fix="Check the 'format' field in rebrew-project.toml matches the actual binary format.",
        )


def check_arch_format(cfg: ProjectConfig) -> CheckResult:
    """Validate arch and format values are known."""
    issues: list[str] = []
    if cfg.arch not in KNOWN_ARCHES:
        issues.append(f"Unknown arch '{cfg.arch}' (known: {', '.join(sorted(KNOWN_ARCHES))})")
    if cfg.binary_format not in KNOWN_FORMATS:
        issues.append(
            f"Unknown format '{cfg.binary_format}' (known: {', '.join(sorted(KNOWN_FORMATS))})"
        )

    if issues:
        return CheckResult(
            name="Arch / Format",
            status=WARN,
            message="; ".join(issues),
            fix="Update 'arch' and 'format' in rebrew-project.toml to supported values.",
        )
    return CheckResult(
        name="Arch / Format",
        status=OK,
        message=f"arch={cfg.arch}, format={cfg.binary_format}",
    )


def toolchain_download_hint(path_str: str) -> str:
    """A download URL for a missing vendored toolchain, keyed by path.

    Matches the nested ``toolchain/<family>/<version>-<arch>`` layout and the
    legacy names (old projects may still reference pre-restructure dirs).
    Order matters: the SP mirrors contain ``msvc/6.0`` and the legacy
    ``msvc6.3``/``msvc6.6`` contain bare ``msvc-6.0``.  Returns the hint text
    (with the leading space) or "" when unknown.
    """
    if "6.0-sp3-win32" in path_str or "msvc6.3" in path_str:
        return " Download: " + _MIRROR.format(repo="msvc600-win9x", asset="msvc6.3.tar.gz")
    if "6.0-sp6-win32" in path_str or "msvc6.6" in path_str:
        return " Download: " + _MIRROR.format(repo="msvc600-win9x", asset="msvc6.6.tar.gz")
    if "7.0-win32" in path_str or "msvc-7.0" in path_str:
        # The decomp.me msvc7.0.tar.gz mirror carries the 7.1 compiler (13.10.3077).
        return " Assemble it: rebrew toolchain vendor msvc-7.0"
    if "5.0-win32" in path_str or "msvc500" in path_str or "msvc-5.0" in path_str:
        return (
            " Download: https://codeload.github.com/archaic-msvc/msvc500/tar.gz/refs/heads/master"
        )
    if "6.0-win32" in path_str or "msvc-6.0" in path_str:
        return " Download: https://github.com/itsmattkc/msvc-6.0-win32"
    if "4.0-win32" in path_str or "msvc-4.0" in path_str:
        return " Download: " + _MIRROR.format(repo="msvc400", asset="MSVC400-master.tar.gz")
    if "4.2-win32" in path_str or "msvc-4.2" in path_str:
        # The vendored 4.2 tree comes from the archaic-msvc repo (its own
        # README + the pinned ToolchainSource); the itsmattkc mirror is a
        # different, older snapshot.
        return (
            " Download: https://codeload.github.com/archaic-msvc/msvc420/tar.gz/refs/heads/master"
        )
    if "wcc" in path_str or "watcom" in path_str:
        return " Download (Watcom C/C++): " + _MIRROR.format(
            repo="watcom1x", asset="wcc11.0.tar.gz"
        )
    if "1.52-win16" in path_str or "msvc152" in path_str:
        return " Download (MSVC 1.52): https://archive.org/details/en_vc152_202512"
    return ""


def image_available(cfg: ProjectConfig, image: str) -> bool:
    """Inspect the same image store as the configured execution backend."""
    from rebrew.compiler.toolchain import image_present

    backend = getattr(cfg, "execution_backend", "")
    if backend and backend != "unshare":
        return image_present(image, runtime=backend)
    return image_present(image)


def check_compiler(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler command is executable."""
    # A 16-bit target needs a profile registered with bits=16 (the same set
    # as arch alignment: MSVC 1.x, Borland 2.0/3.1, Watcom wcc, Delphi 1.0,
    # and any plugin that declares bits=16).  With one configured, proceed
    # to the image check; otherwise a 32-bit compiler cannot build the
    # target, so a missing toolchain is expected, not a project defect.
    # Downgrade to a warning and suggest a profile via the detector.
    from rebrew.toolchain_detect import bitness16_profiles

    profiles_16 = bitness16_profiles()
    if (
        getattr(cfg, "arch", "") == "x86_16"
        and getattr(cfg, "compiler_profile", "") not in profiles_16
    ):
        hint = (
            "msvc-1.52"
            if "msvc-1.52" in profiles_16
            else (profiles_16[0] if profiles_16 else "msvc-1.52")
        )
        try:
            from rebrew.toolchain_detect import detect_toolchain, suggest_profile

            info = detect_toolchain(cfg.target_binary)
            guess = suggest_profile(info, cfg.target_binary)
            if guess:
                hint = guess
        except OSError, ValueError, ImportError, AttributeError:
            logger.debug("profile suggestion failed", exc_info=True)  # best-effort recommendation
        return CheckResult(
            name="Compiler",
            status=WARN,
            message="16-bit target — configure a 16-bit compiler profile for "
            f"byte matching (e.g. '{hint}')",
            fix=f'Set compiler.profile = "{hint}"; analysis/docs work either way.',
        )

    # Every shipped profile compiles through its image. Only a profile without a
    # registry spec (or an image-less plugin one) falls through to the
    # legacy executable check.
    from rebrew.compiler.toolchain import TOOLCHAINS

    _profile = str(getattr(cfg, "compiler_profile", ""))
    _spec = TOOLCHAINS.get(_profile) if _profile else None
    if _spec is not None and _spec.image is not None:
        if image_available(cfg, _spec.image):
            return CheckResult(
                name="Compiler",
                status=OK,
                message=f"{_profile} toolchain image {_spec.image} ready",
            )
        return CheckResult(
            name="Compiler",
            status=FAIL,
            message=f"{_profile} toolchain image {_spec.image} not built",
            fix=f"Run `rebrew toolchain build {_profile}`.",
        )
    if _spec is not None and _spec.runtime != "native":
        return CheckResult(
            name="Compiler",
            status=FAIL,
            message=f"{_profile} has no toolchain image — host execution is unsupported",
            fix=f"Run `rebrew toolchain build {_profile}` first.",
        )

    cmd_str = cfg.compiler_command
    if not cmd_str:
        return CheckResult(
            name="Compiler",
            status=FAIL,
            message="No compiler command configured",
            fix="Set [compiler] profile to an image-backed toolchain, or command for a native compiler.",
        )

    try:
        parts = shlex.split(cmd_str)
    except ValueError:
        parts = cmd_str.split()

    exe = parts[0] if parts else ""
    exe_path = shutil.which(exe)
    is_wibo_runner = Path(exe).name == "wibo"
    # A relative command (e.g. toolchain/msvc/1.52-win16/BIN/CL.EXE) resolves against the
    # project root — do not require it on PATH (msvc-1.52's direct DOSBox
    # command, or a plugin toolchain's vendored path).
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
                hint = toolchain_download_hint(str(exe).lower())
                return CheckResult(
                    name="Compiler",
                    status=FAIL,
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
                    status=WARN,
                    message="wibo runner not found",
                    fix=(
                        "Run 'rebrew init --install-wibo' or set compiler.command "
                        "to the wibo binary path."
                    ),
                )
            exe_path = str(found)

    # For Wine/wibo-based compilers, check the CL.EXE path.
    wine_path = shutil.which("wine") if exe == "wine" else None
    if exe == "wine" and wine_path is None:
        return CheckResult(
            name="Compiler",
            status=FAIL,
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
                        + toolchain_download_hint(str(cl_path).lower())
                    )

                    return CheckResult(
                        name="Compiler",
                        status=FAIL,
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
                from rebrew.compiler.compile import maybe_headless_wine
                from rebrew.utils import run_process_group

                smoke_cmd, smoke_env = maybe_headless_wine(
                    [runner_token, str(cl_path)],
                    {**os.environ, "WINEDEBUG": "-all"},
                )
                run_process_group(
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
                    status=OK,
                    message=f"{display_runner} + {cl_path.name} (reachable){note}",
                )
            except subprocess.TimeoutExpired:
                return CheckResult(
                    name="Compiler",
                    status=WARN,
                    message=f"{display_runner} + {cl_path.name} (timed out on smoke test)",
                    fix="The runner may be slow to start. This is usually fine for actual compilation.",
                )
            except (FileNotFoundError, OSError) as e:
                return CheckResult(
                    name="Compiler",
                    status=FAIL,
                    message=f"Failed to invoke {display_runner}: {e}",
                    fix="Check the runner installation and CL.EXE path.",
                )
            except ValueError as e:
                return CheckResult(
                    name="Compiler",
                    status=FAIL,
                    message=str(e),
                    fix="Set REBREW_WINE_HEADLESS to 0 or 1, or unset it.",
                )
        if exe == "wine":
            return CheckResult(
                name="Compiler",
                status=WARN,
                message=f"Wine found at {wine_path}, but no CL.EXE path specified in compiler.command",
                fix="Set compiler.command to 'wine /path/to/CL.EXE' in rebrew-project.toml.",
            )
        return CheckResult(
            name="Compiler",
            status=WARN,
            message="wibo runner configured, but no CL.EXE path specified in compiler.command",
            fix="Set compiler.command to 'wibo /path/to/CL.EXE' in rebrew-project.toml.",
        )

    return CheckResult(
        name="Compiler",
        status=OK,
        message=f"Found: {exe_path or exe}",
    )


def check_toolchain_alignment(
    cfg: ProjectConfig,
    *,
    exclude_ranges_fn: Any = None,
) -> CheckResult:
    """Check that the configured compiler profile aligns with the binary.

    Uses the layered toolchain detector (diec -> PDB -> PE metadata -> heuristics) to guess
    what actually built the target and compares it against the configured
    ``[compiler] profile``.  A mismatch means byte-matching is impossible —
    the user should switch profiles or document blockers.
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return CheckResult(name="Toolchain alignment", status=SKIP, message="binary not available")

    from rebrew.toolchain_detect import (
        DIE_UNAVAILABLE,
        detect_toolchain,
        profile_matches_detection,
    )

    try:
        # Game code only: library bands (`external_ranges`) were compiled with
        # Microsoft's own settings and must not decide the code-generator family.
        excluded = exclude_ranges_fn(cfg) if exclude_ranges_fn is not None else []
        info = detect_toolchain(binary, exclude_ranges=excluded)
    except Exception as exc:  # a broken detector must not kill the doctor
        return CheckResult(
            name="Toolchain alignment", status=SKIP, message=f"detection failed: {exc}"
        )

    profile = getattr(cfg, "compiler_profile", "") or "msvc-6.0"
    if info.family == "unknown":
        return CheckResult(
            name="Toolchain alignment",
            status=SKIP,
            message="binary compiler family not identified",
        )

    aligned, explanation = profile_matches_detection(profile, info)
    detail = f"detected {info.family} ({info.version_hint or 'unknown version'})"
    if info.codegen:
        detail += f"; code generator: {info.codegen}"
    if info.detected_by:
        from rebrew.toolchain_detect import backend_display_name

        detail += f" via {backend_display_name(info.detected_by)}"
    if DIE_UNAVAILABLE in info.evidence:
        detail += "; diec not found (add tools/diec or PATH diec for stronger detection)"
    if info.flags:
        detail += f"; PDB flags: {' '.join(info.flags)}"
    if aligned:
        if explanation:
            return CheckResult(
                name="Toolchain alignment", status=WARN, message=detail, fix=explanation
            )
        return CheckResult(name="Toolchain alignment", status=OK, message=detail)
    # Families no rebrew compiler profile can ever match (e.g. Borland
    # Delphi) are a documented-blocker situation, not a broken project:
    # intake already marks their functions BLOCKER and analysis works.
    # Downgrade to a warning so `rebrew doctor` reports a healthy analysis
    # project instead of a misleading hard failure.
    if info.family == "delphi":
        return CheckResult(
            name="Toolchain alignment",
            status=WARN,
            message=detail,
            fix=explanation
            or "Delphi functions are documented as blockers — analysis works, matching does not.",
        )
    return CheckResult(
        name="Toolchain alignment",
        status=FAIL,
        message=detail,
        fix=explanation or "Switch the [compiler] profile to match the detected family.",
    )


def check_toolchain_backed(cfg: ProjectConfig) -> CheckResult:
    """Check the image; a vendored build-source tree cannot replace it."""
    profile = str(getattr(cfg, "compiler_profile", ""))
    from rebrew.compiler.toolchain import ToolchainError, get_toolchain

    try:
        spec = get_toolchain(profile)
    except ToolchainError:
        return CheckResult(name="Toolchain", status=SKIP, message="not a toolchain-backed profile")
    if spec.withdrawn:
        # Not offered: no build, pull or vendor would make it the compiler it claims.
        return CheckResult(
            name="Toolchain",
            status=FAIL,
            message=f"{profile} is withdrawn: {spec.withdrawn}",
            fix="Choose another [compiler] profile (`rebrew toolchain list`).",
        )
    if spec.image is None:
        return CheckResult(
            name="Toolchain", status=SKIP, message="not an image-backed profile (native binary)"
        )

    image_ok = image_available(cfg, spec.image)
    host_present = spec.host_path is not None and Path(spec.host_path).exists()
    bits = [f"image {spec.image} pulled"] if image_ok else []
    if host_present:
        bits.append(f"vendored tree {spec.host_path} present (build source)")
    ready = image_ok
    status = OK if ready else FAIL
    message = f"{profile}: {' + '.join(bits) if bits else 'toolchain image not built'}"
    fix = "" if ready else f"Run `rebrew toolchain build {profile}`."
    return CheckResult(name="Toolchain", status=status, message=message, fix=fix)


def check_cache_backend(cfg: ProjectConfig) -> CheckResult:
    """The configured compile-cache backend must be a registered backend.

    ``load_config`` already rejects an unknown ``[cache] backend``; this
    check still catches a programmatic ``ProjectConfig`` / doctor probe that
    bypassed the loader.
    """
    from rebrew.compiler.cache import DEFAULT_CACHE_BACKEND, available_cache_backends

    backend = str(getattr(cfg, "cache_backend", DEFAULT_CACHE_BACKEND))

    known = available_cache_backends()
    if backend in known:
        return CheckResult(
            name="Cache",
            status=OK,
            message=f"[cache] backend = {backend}",
            fix="",
        )
    return CheckResult(
        name="Cache",
        status=FAIL,
        message=f"[cache] backend = {backend!r} is not a registered backend",
        fix=(
            f"Known backends: {', '.join(known)} — set [cache] backend in "
            "rebrew-project.toml or install the plugin that provides it"
        ),
    )


def check_runner(cfg: ProjectConfig) -> CheckResult:
    """Check the selected image backend, probing namespaces for unshare."""
    from rebrew.compiler.toolchain import TOOLCHAINS

    _profile = str(getattr(cfg, "compiler_profile", ""))
    _spec = TOOLCHAINS.get(_profile) if _profile else None
    if _spec is not None and _spec.image is not None:
        from rebrew.compiler.toolchain import ToolchainError, check_experimental_unshare
        from rebrew.utils import container_runtime

        backend = getattr(cfg, "execution_backend", "") or container_runtime()
        if image_available(cfg, _spec.image):
            if backend == "unshare":
                try:
                    check_experimental_unshare(_spec)
                except ToolchainError as exc:
                    return CheckResult(name="Runner", status=FAIL, message=f"unshare: {exc}")
            return CheckResult(
                name="Runner", status=OK, message=f"{backend}: image {_spec.image} ready"
            )
        return CheckResult(
            name="Runner",
            status=WARN,
            message=f"{backend}: image {_spec.image} not built",
            fix=f"Run `rebrew toolchain build {_profile}`.",
        )

    runner = str(getattr(cfg, "compiler_runner", "")).strip()
    if not runner:
        return CheckResult(
            name="Runner", status=OK, message="No runner configured (native compiler)"
        )

    if Path(runner).name == "wibo":
        # `init --install-wibo` writes a relative runner like tools/wibo —
        # resolve it against the project root (and fall back to the shared
        # wibo cache / PATH).
        if shutil.which(runner):
            return CheckResult(name="Runner", status=OK, message=f"{runner} found in PATH")
        local = Path(runner) if Path(runner).is_absolute() else cfg.root / Path(runner)
        if local.exists():
            return CheckResult(name="Runner", status=OK, message=f"wibo found at {local}")
        from rebrew.wibo import find_wibo

        found = find_wibo(cfg.root)
        if found:
            return CheckResult(name="Runner", status=OK, message=f"wibo found at {found}")
        return CheckResult(
            name="Runner",
            status=WARN,
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
                status=OK,
                message=(
                    "Wine (checked by compiler check); wibo also available in "
                    "tools/ — wibo is faster but fails on some tools, wine "
                    "remains the default"
                ),
            )
        return CheckResult(name="Runner", status=OK, message="Wine (checked by compiler check)")

    if shutil.which(runner):
        return CheckResult(name="Runner", status=OK, message=f"{runner} found in PATH")

    return CheckResult(name="Runner", status=WARN, message=f"Unknown runner '{runner}'")


def image_toolchain_check(cfg: ProjectConfig, name: str, what: str) -> CheckResult | None:
    """The image supplies includes/libs; native profiles use host-path checks."""
    from rebrew.compiler.toolchain import TOOLCHAINS

    profile = str(getattr(cfg, "compiler_profile", ""))
    spec = TOOLCHAINS.get(profile) if profile else None
    if spec is None or spec.image is None:
        return None
    if image_available(cfg, spec.image):
        return CheckResult(
            name=name,
            status=OK,
            message=f"{profile}: {what} provided by toolchain image {spec.image}",
        )
    return CheckResult(
        name=name,
        status=WARN,
        message=f"{profile}: toolchain image {spec.image} not built",
        fix=f"Run `rebrew toolchain build {profile}`.",
    )


_DEFAULT_IMAGE_TOOLCHAIN_CHECK = image_toolchain_check


def check_includes(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler include directory exists."""
    # A 16-bit target without a bits=16 profile has no usable compile path —
    # the include dir is moot, same as the compiler check.  The set is the
    # toolchain registry (not a hardcoded name list): exempting only
    # msvc-1.52 told a working borland, watcom, msvc-1.0, or msvc-1.5 project
    # to switch toolchains.  With one configured, the vendored INCLUDE is
    # staged into the sandbox as C:\INCLUDE, so the host path check still applies.
    from rebrew.toolchain_detect import bitness16_profiles

    profiles_16 = bitness16_profiles()
    if (
        getattr(cfg, "arch", "") == "x86_16"
        and getattr(cfg, "compiler_profile", "") not in profiles_16
    ):
        return CheckResult(
            name="Include path",
            status=WARN,
            message="16-bit NE target — configure a 16-bit profile for includes",
            fix="Set compiler.profile to one of "
            + ", ".join(profiles_16)
            + " (its vendored INCLUDE is staged as C:\\INCLUDE in the sandbox).",
        )
    image_check = resolve_pkg_hook(
        "_image_toolchain_check", image_toolchain_check, _DEFAULT_IMAGE_TOOLCHAIN_CHECK
    )
    image = image_check(cfg, "Include path", "includes")
    if image is not None:
        return image
    inc_path = Path(compiler_dir(cfg.compiler_includes))
    if not inc_path.parts:
        # Explicitly empty means "the toolchain ships its own headers"
        # (docs/CONFIG.md); Path("") would glob the current directory and
        # report a header count that has nothing to do with the compiler.
        return CheckResult(
            name="Include path",
            status=SKIP,
            message="no compiler.includes configured (toolchain provides headers)",
        )
    if not inc_path.exists():
        return CheckResult(
            name="Include path",
            status=FAIL,
            message=f"Not found: {inc_path}",
            fix="Set compiler.includes in rebrew-project.toml to the MSVC include directory.",
        )
    # Count header files
    headers = list(inc_path.glob("*.h")) + list(inc_path.glob("*.H"))
    return CheckResult(
        name="Include path",
        status=OK,
        message=f"{inc_path} ({len(headers)} headers)",
    )


def check_libs(cfg: ProjectConfig) -> CheckResult:
    """Check that the compiler lib directory exists."""
    image_check = resolve_pkg_hook(
        "_image_toolchain_check", image_toolchain_check, _DEFAULT_IMAGE_TOOLCHAIN_CHECK
    )
    image = image_check(cfg, "Lib path", "libs")
    if image is not None:
        return image
    lib_path = Path(compiler_dir(cfg.compiler_libs))
    if not lib_path.parts:
        return CheckResult(
            name="Lib path",
            status=SKIP,
            message="no compiler.libs configured (nothing to link against on the host)",
        )
    if not lib_path.exists():
        return CheckResult(
            name="Lib path",
            status=WARN,
            message=f"Not found: {lib_path}",
            fix="Set compiler.libs in rebrew-project.toml if linking is required.",
        )
    libs = list(lib_path.glob("*.lib")) + list(lib_path.glob("*.LIB"))
    return CheckResult(
        name="Lib path",
        status=OK,
        message=f"{lib_path} ({len(libs)} libs)",
    )


def check_function_list(cfg: ProjectConfig) -> CheckResult:
    """Check that the discovery inventory exists and parses."""
    from rebrew.catalog import cached_function_list
    from rebrew.metadata.bindings import min_valid_va_for

    inv_path = inventory_path_for(cfg.reversed_dir, cfg)
    if not inv_path.exists():
        return CheckResult(
            name="Function inventory",
            status=WARN,
            message=f"Not found: {inv_path}",
            fix=(
                "Run `rebrew intake` or `rebrew binary functions "
                "--output src/<target>/function_structure.json`."
            ),
        )

    try:
        funcs = cached_function_list(cfg)
        min_va = min_valid_va_for(cfg)
        valid = sum(1 for f in funcs if (va := f.get("va")) is not None and int(va) >= min_va)
        if valid == 0:
            return CheckResult(
                name="Function inventory",
                status=WARN,
                message=f"{inv_path.name} has no parseable entries",
                fix="Regenerate it with `rebrew binary functions`.",
            )
        return CheckResult(
            name="Function inventory",
            status=OK,
            message=f"{inv_path.name} ({valid} entries)",
        )
    except (OSError, ValueError, KeyError) as e:
        return CheckResult(
            name="Function inventory",
            status=FAIL,
            message=f"Cannot read: {e}",
            fix="Check file permissions.",
        )


def check_source_files(cfg: ProjectConfig) -> CheckResult:
    """Check that at least one source file exists in reversed_dir."""
    reversed_dir: Path = cfg.reversed_dir
    if not reversed_dir.exists():
        return CheckResult(
            name="Source files",
            status=WARN,
            message=f"Directory not found: {reversed_dir}",
            fix=f"Create the directory: mkdir -p {shlex.quote(str(reversed_dir))}",
        )

    from rebrew.source.discovery import iter_sources

    sources = iter_sources(reversed_dir, cfg)
    if not sources:
        ext = getattr(cfg, "source_ext", ".c")
        return CheckResult(
            name="Source files",
            status=WARN,
            message=f"No *{ext} files in {reversed_dir}",
            fix="Use 'rebrew skeleton 0xVA' to generate initial source files.",
        )

    return CheckResult(
        name="Source files",
        status=OK,
        message=f"{len(sources)} source file(s) in {reversed_dir}",
    )


def check_function_bindings(cfg: ProjectConfig) -> CheckResult:
    """Report function records whose source's address anchor names another function.

    Every read skips such a record, so its function is missing from coverage, status and
    verification until the record and the source agree.
    """
    from rebrew.config import target_module
    from rebrew.metadata.bindings import binding_conflicts, iter_source_bindings
    from rebrew.source.discovery import iter_sources

    name = "Function bindings"
    if not cfg.reversed_dir.exists():
        return CheckResult(name=name, status=SKIP, message="No source directory")
    with binding_conflicts() as conflicts:
        iter_source_bindings(
            iter_sources(cfg.reversed_dir, cfg),
            target=target_module(cfg),
            metadata_dir=cfg.metadata_dir,
        )
    if not conflicts:
        return CheckResult(
            name=name, status=OK, message="Every source anchor agrees with its record"
        )
    keys = [f"{module}.0x{va:08x}" for module, va in sorted(conflicts)]
    shown = ", ".join(keys[:_BINDING_CONFLICTS_SHOWN])
    more = len(keys) - _BINDING_CONFLICTS_SHOWN
    return CheckResult(
        name=name,
        status=WARN,
        message=(
            f"{len(keys)} function record(s) disagree with their source's address anchor and "
            f"are skipped by every read: {shown}{f', and {more} more' if more > 0 else ''}"
        ),
        fix=(
            "Re-run rebrew intake to repair a generated stub whose record holds a name that is "
            "no C identifier; otherwise rename the source or the record so both name one function."
        ),
    )


def check_metadata_files(cfg: ProjectConfig) -> CheckResult:
    """Check that rebrew-functions.toml and rebrew-data.toml exist in metadata_dir."""
    metadata_dir: Path = cfg.metadata_dir
    func_toml = metadata_dir / "rebrew-functions.toml"
    data_toml = metadata_dir / "rebrew-data.toml"
    missing: list[str] = []
    if not metadata_store(func_toml).exists():
        missing.append("rebrew-functions.toml")
    if not metadata_store(data_toml).exists():
        missing.append("rebrew-data.toml")

    if missing:
        return CheckResult(
            name="Metadata TOML",
            status=WARN,
            message=f"Missing in {metadata_dir}: {', '.join(missing)}",
            fix="Create with: touch "
            + " ".join(shlex.quote(str(metadata_dir / f)) for f in missing),
        )
    return CheckResult(
        name="Metadata TOML",
        status=OK,
        message=f"rebrew-functions.toml + rebrew-data.toml in {metadata_dir}",
    )


def check_bin_dir(cfg: ProjectConfig) -> CheckResult:
    """Check that the output bin directory exists or can be created."""
    bin_dir: Path = cfg.bin_dir
    if bin_dir.exists():
        return CheckResult(
            name="Bin directory",
            status=OK,
            message=str(bin_dir),
        )
    # Not a failure — it will be created on first compile
    return CheckResult(
        name="Bin directory",
        status=OK,
        message=f"{bin_dir} (will be created on first compile)",
    )


def check_shared_sources(cfg: ProjectConfig) -> CheckResult:
    """Check shared-source setup for multi-target projects.

    Single-target projects need nothing.  Multi-target projects sharing one
    codebase (same game logic in several binaries) want ``src/shared`` with
    one ``/* ADDRESS: <module> <va> */`` anchor per target (ADR-010) plus
    ``source import-related --shared`` instead of per-target copies that drift
    apart.
    Warns when the project has several targets but no shared dir, or when the
    configured shared dir does not exist.
    """
    targets = list(getattr(cfg, "all_targets", []) or [])
    if len(targets) < 2:
        return CheckResult(
            name="Shared sources",
            status=SKIP,
            message="Single-target project — no shared sources needed",
        )
    shared = getattr(cfg, "shared_dir", None)
    if shared is None:
        return CheckResult(
            name="Shared sources",
            status=WARN,
            message=f"{len(targets)} targets but shared_dir is disabled",
            fix="Enable with `rebrew cfg set project.shared_dir 'src/shared'` "
            "and `rebrew source import-related --from <src> --shared` for shared functions.",
        )
    if not Path(shared).is_dir():
        return CheckResult(
            name="Shared sources",
            status=WARN,
            message=f"{len(targets)} targets sharing one codebase but {shared} is missing",
            fix=f"Create with: mkdir -p {shlex.quote(str(shared))} — then `rebrew source import-related "
            "--from <src> --shared` stacks one address anchor per target on one file.",
        )
    return CheckResult(
        name="Shared sources",
        status=OK,
        message=f"{shared} serves {len(targets)} targets",
    )


def check_external_libs(cfg: ProjectConfig) -> CheckResult:
    """Check the external ``.lib`` flag (``targets.<name>.external_libs``).

    The map flags external library code — "not our work": its modules leave
    the progress accounting, ``rebrew library match`` ingests the archives by
    default, and ``rebrew build cmake-sources`` emits the non-empty specs as
    ``REBREW_EXTERNAL_LIBS`` so the build links the stock archive at build
    time instead of compiling reversed copies.
    """
    libs = dict(getattr(cfg, "external_libs", None) or {})
    if not libs:
        return CheckResult(
            name="External libraries",
            status=SKIP,
            message="none flagged (targets.<name>.external_libs)",
        )

    missing: list[str] = []
    for mod, spec in sorted(libs.items()):
        s = (spec or "").strip()
        if "/" not in s and "\\" not in s:
            continue  # bare archive name — resolved by the linker/toolchain
        p = Path(s)
        if not (p if p.is_absolute() else cfg.root / p).exists():
            missing.append(f"{mod}={s}")
    if missing:
        return CheckResult(
            name="External libraries",
            status=WARN,
            message=f"{len(libs)} flagged module(s); archive(s) not found: {', '.join(missing)}",
            fix="Point each external_libs spec at the archive to link "
            '(or "" for identified-only modules).',
        )
    linked = sum(1 for spec in libs.values() if (spec or "").strip())
    return CheckResult(
        name="External libraries",
        status=OK,
        message=f"{len(libs)} flagged module(s); {linked} link as stock archives",
    )


def check_layout_package(cfg: ProjectConfig) -> CheckResult:
    """Check that the layout package exists for byte-identity build steps."""
    pkg = Path(cfg.root) / "layout" / cfg.target_name / "rebrew-layout.toml"
    if pkg.is_file():
        return CheckResult(
            name="Layout package",
            status=OK,
            message=str(pkg),
        )
    # Warn, not fail: only data/calibrate-bss/postlink/round-trip need it.
    return CheckResult(
        name="Layout package",
        status=WARN,
        message=f"Not found: {pkg}",
        fix=f"Run `rebrew build layout --target {cfg.target_name}`.",
    )


def check_backup_readiness(cfg: ProjectConfig) -> CheckResult:
    """Report whether the durable stores can be backed up and restored.

    Read-only: this never writes a backup.  A project whose durable
    stores are missing, or whose active backend has no rebrew-side
    backup command (PostgreSQL), is not restore-ready — the operator
    must know that before the tree is lost, not after.
    """
    backend = getattr(cfg, "metadata_backend", "toml")
    if backend == "pgsql":
        # Any `.rebrew/pgsql-before-transfer/` snapshot is the only copy
        # of the destination a migrate replaced; the pgsql WARN must not
        # swallow that the snapshots themselves ride in the metadata
        # backup bundle (extra_durable_sources covers them).
        snapshot_dir = Path(cfg.root) / ".rebrew" / "pgsql-before-transfer"
        snapshot_note = (
            " + "
            + str(len([p for p in snapshot_dir.rglob("*.toml") if p.is_file()]))
            + " before-transfer snapshot(s) carried by the metadata backup"
            if snapshot_dir.is_dir()
            else ""
        )
        return CheckResult(
            name="Backup readiness",
            status=WARN,
            message="PostgreSQL backend has no rebrew-side backup command" + snapshot_note,
            fix="Back up with pg_dump (see the rebrew repo's docs/METADATA.md#postgresql-backup-and-restore) "
            "plus `rebrew metadata backup` for the project files.",
        )
    root = Path(cfg.root)
    from rebrew.metadata.sqlite import extra_durable_sources, toml_store_trees

    if backend == "sqlite":
        database = root / "rebrew-metadata.sqlite3"
        if not database.is_file():
            return CheckResult(
                name="Backup readiness",
                status=WARN,
                message=f"Metadata database not found: {database}",
                fix="Create it with `rebrew metadata migrate sqlite`.",
            )
        extras = len(extra_durable_sources(root))
        binary = getattr(cfg, "target_binary", None)
        binary_note = (
            f" Target binary {Path(binary).name} is not regenerable — "
            "it rides in the SQLite backup bundle; copy the bundle off-tree."
            if binary is not None and Path(binary).exists()
            else ""
        )
        binsync_dir = getattr(cfg, "binsync_state_dir", "") or ""
        binsync_note = (
            f" + BinSync state dir {binsync_dir} (rides in the backup bundle)"
            if binsync_dir and Path(binsync_dir).expanduser().is_dir()
            else ""
        )
        return CheckResult(
            name="Backup readiness",
            status=OK,
            message=f"SQLite database + {extras} .rebrew/ extra(s) back up with "
            f"`rebrew metadata backup --dir <off-tree>`{binsync_note}" + binary_note,
        )
    # The target binary is not regenerable from anything rebrew holds:
    # an operator who loses it loses the reference the whole project
    # verifies against.  Warn when it is not backed up alongside the
    # stores so the gap is visible before the tree is lost.
    binary = getattr(cfg, "target_binary", None)
    binary_note = ""
    if binary is not None and Path(binary).exists():
        binary_note = (
            f" Target binary {Path(binary).name} is not regenerable — "
            "it rides in the TOML backup bundle; copy the bundle off-tree."
        )
    trees = toml_store_trees(root)
    if not trees:
        return CheckResult(
            name="Backup readiness",
            status=WARN,
            message=f"No managed TOML stores under {root}" + binary_note,
            fix="Create them with `rebrew intake` or restore an existing backup.",
        )
    extras = len(extra_durable_sources(root))
    binsync_dir = getattr(cfg, "binsync_state_dir", "") or ""
    binsync_note = (
        f" + BinSync state dir {binsync_dir} (rides in the backup bundle)"
        if binsync_dir and Path(binsync_dir).expanduser().is_dir()
        else ""
    )
    return CheckResult(
        name="Backup readiness",
        status=OK,
        message=f"{len(trees)} TOML store tree(s) + {extras} .rebrew/ extra(s) back up with "
        f"`rebrew metadata backup --dir <off-tree>`{binsync_note}" + binary_note,
    )
