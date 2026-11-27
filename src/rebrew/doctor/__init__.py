"""doctor – Diagnostic command for rebrew project health.

Environment/setup health plus source/record binding conflicts. It does not
run lint's full corpus audit; metadata placement, VA-vs-function-list
consistency and per-function settings remain in ``rebrew lint``. Doctor
checks config, target binary, arch/format, toolchain alignment, compiler
image/executable, runner, include/lib paths, function-list existence,
source-dir existence, metadata-file existence, integration tooling, and
whether source bindings disagree with stored function identities.

Usage::

    rebrew doctor
    rebrew doctor --target client_exe
    rebrew doctor --json
"""

from typing import Any
lazy import shutil as shutil

import typer

from rebrew.cli import EXIT_ERROR, TargetOption, json_print
from rebrew.cli import console as console
from rebrew.doctor.checks import (
    FAIL,
    KNOWN_ARCHES,
    OK,
    SKIP,
    WARN,
    image_available,
    image_toolchain_check,
    toolchain_download_hint,
)
from rebrew.doctor.checks import (
    CheckResult as CheckResult,
)
from rebrew.doctor.checks import (
    DoctorReport as DoctorReport,
)
from rebrew.doctor.checks import (
    LibIndexUnavailable as LibIndexUnavailable,
)
from rebrew.doctor.checks import (
    check_arch_format as check_arch_format,
)
from rebrew.doctor.checks import (
    check_backup_readiness as check_backup_readiness,
)
from rebrew.doctor.checks import (
    check_bin_dir as check_bin_dir,
)
from rebrew.doctor.checks import (
    check_cache_backend as check_cache_backend,
)
from rebrew.doctor.checks import (
    check_compiler as check_compiler,
)
from rebrew.doctor.checks import (
    check_config_parse as check_config_parse,
)
from rebrew.doctor.checks import (
    check_external_libs as check_external_libs,
)
from rebrew.doctor.checks import (
    check_function_bindings as check_function_bindings,
)
from rebrew.doctor.checks import (
    check_function_list as check_function_list,
)
from rebrew.doctor.checks import (
    check_includes as check_includes,
)
from rebrew.doctor.checks import (
    check_layout_package as check_layout_package,
)
from rebrew.doctor.checks import (
    check_libs as check_libs,
)
from rebrew.doctor.checks import (
    check_metadata_files as check_metadata_files,
)
from rebrew.doctor.checks import (
    check_runner as check_runner,
)
from rebrew.doctor.checks import (
    check_shared_sources as check_shared_sources,
)
from rebrew.doctor.checks import (
    check_source_files as check_source_files,
)
from rebrew.doctor.checks import (
    check_target_binary as check_target_binary,
)
from rebrew.doctor.checks import (
    check_toolchain_alignment as base_check_toolchain_alignment,
)
from rebrew.doctor.checks import (
    check_toolchain_backed as check_toolchain_backed,
)
from rebrew.doctor.integrations import (
    check_binsync_state as check_binsync_state,
)
from rebrew.doctor.integrations import (
    check_crt_linkage as check_crt_linkage,
)
from rebrew.doctor.integrations import (
    check_decompilers as check_decompilers,
)
from rebrew.doctor.integrations import (
    check_flirt_sigs as base_check_flirt_sigs,
)
from rebrew.doctor.integrations import (
    check_ghidra_sync as check_ghidra_sync,
)
from rebrew.doctor.integrations import (
    check_opt_level as base_check_opt_level,
)
from rebrew.doctor.integrations import (
    check_optional_tools as base_check_optional_tools,
)
from rebrew.doctor.integrations import (
    inventory_spans,
)
from rebrew.doctor.integrations import (
    libcmt_index as base_libcmt_index,
)
from rebrew.doctor.integrations import (
    library_site_counts as base_library_site_counts,
)
from rebrew.doctor.integrations import (
    render_doctor as render_doctor,
)
from rebrew.doctor.integrations import (
    run_doctor as run_doctor,
)
lazy from rebrew.config import ProjectConfig as ProjectConfig
lazy from rebrew.config import load_config as load_config
lazy from rebrew.errors import RebrewError as RebrewError


def _match_helpers() -> tuple[Any, ...]:
    from rebrew.library.match import (
        PREFIX_BYTES,
        ensure_stock_lib,
        index_library,
        match_bytes,
        match_leading_body,
        stock_lib_cache,
    )

    return (
        ensure_stock_lib,
        index_library,
        stock_lib_cache,
        PREFIX_BYTES,
        match_bytes,
        match_leading_body,
    )


def check_toolchain_alignment(cfg: ProjectConfig) -> CheckResult:
    """Check that the configured compiler profile aligns with the binary."""
    from rebrew.toolchain_cli import external_ranges

    return base_check_toolchain_alignment(cfg, exclude_ranges_fn=external_ranges)


def check_optional_tools() -> CheckResult:
    """Check angr and its bundled Claripy solver for symbolic proving."""
    from rebrew.matching.prove import (
        PROVE_CHECKOUT_INSTALL,
        PROVE_TOOL_INSTALL,
        angr_available,
    )

    return base_check_optional_tools(
        angr_available_fn=angr_available,
        checkout_install=PROVE_CHECKOUT_INSTALL,
        tool_install=PROVE_TOOL_INSTALL,
    )


def check_flirt_sigs(cfg: ProjectConfig) -> CheckResult:
    """Check FLIRT signatures and optional python-flirt parser availability."""
    from rebrew.library.flirt import parse_signature_file

    return base_check_flirt_sigs(cfg, parse_signature_fn=parse_signature_file)


def libcmt_index(cfg: Any) -> Any:
    """Indexed stock LIBCMT archive."""
    return base_libcmt_index(cfg, match_helpers=_match_helpers())


def library_site_counts(cfg: Any, info: Any) -> tuple[int, int] | None:
    """How many wrapper sites sit in a statically linked stock LIBCMT body."""
    return base_library_site_counts(cfg, info, match_helpers=_match_helpers())


def check_opt_level(cfg: ProjectConfig) -> CheckResult:
    """Check the project's optimization flag against the binary's detected one."""
    from rebrew.toolchain_cli import external_ranges

    return base_check_opt_level(cfg, exclude_ranges_fn=external_ranges)


# Local `_`-aliases retained for test compatibility (never imported across modules).
_OK = OK
_FAIL = FAIL
_WARN = WARN
_SKIP = SKIP
_KNOWN_ARCHES = KNOWN_ARCHES
_image_available = image_available
_image_toolchain_check = image_toolchain_check
_inventory_spans = inventory_spans
_libcmt_index = libcmt_index
_library_site_counts = library_site_counts
_toolchain_download_hint = toolchain_download_hint

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew doctor\n\n"
    "  rebrew doctor --target mygame\n\n"
    "  rebrew doctor --json\n\n"
    "[dim]Checks project configuration, target binary/architecture, toolchain and runner, include/library paths, function inventory, source directories, and metadata files. Use rebrew lint for per-function bindings, metadata fields, flags, and corpus conventions. Returns 0 when checks pass, 2 for failed prerequisites or configuration.[/dim]\n\n"
)

app = typer.Typer(
    help="Diagnostic checks for rebrew project health.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Run diagnostic checks on the rebrew project."""
    report = run_doctor(target=target)

    if json_output:
        json_print(report.to_dict())
    else:
        render_doctor(report)

    if not report.passed:
        # A failing check is always a missing prerequisite, an unreadable
        # config, or an unusable toolchain — never a byte mismatch, which is
        # what EXIT_MISMATCH is reserved for.  `rebrew todo` in the same
        # directory reports the same missing rebrew-project.toml as
        # EXIT_ERROR, and a script must not have to special-case doctor.
        raise typer.Exit(code=EXIT_ERROR)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
