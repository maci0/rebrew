"""status – At-a-glance reversing progress overview.

Aggregates coverage data from annotations, function structure, and verify
cache into a concise project health dashboard.  No compilation is performed.

Usage::

    rebrew status                   Quick project overview
    rebrew status --json            Machine-readable JSON output
    rebrew status --target client_exe     Status for a specific target
"""

import typer

from rebrew.cli import (
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    json_print,
    option_default,
    require_config,
)
from rebrew.cli import (
    console as console,
)
from rebrew.status.collect import (
    CODE_ACCOUNT_CAPTION as CODE_ACCOUNT_CAPTION,
)
from rebrew.status.collect import (
    SourceData as SourceData,
)
from rebrew.status.collect import (
    StatusReport as StatusReport,
)
from rebrew.status.collect import (
    VerifyInfo as VerifyInfo,
)
from rebrew.status.collect import (
    attach_file_similarity,
    compute_text_size,
    initialized_data_ranges,
    load_cache_raw,
    load_verify_info,
    target_binary,
)
from rebrew.status.collect import (
    classify_text_gaps as classify_text_gaps,
)
from rebrew.status.collect import (
    classify_unattributed_ranges as classify_unattributed_ranges,
)
from rebrew.status.collect import (
    code_account_headline as code_account_headline,
)
from rebrew.status.collect import (
    code_account_parts as code_account_parts,
)
from rebrew.status.collect import (
    collect_status as collect_status,
)
from rebrew.status.collect import (
    compare_file_bytes as compare_file_bytes,
)
from rebrew.status.collect import (
    data_byte_coverage as data_byte_coverage,
)
from rebrew.status.collect import (
    effective_status as effective_status,
)
from rebrew.status.collect import (
    find_built_image as find_built_image,
)
from rebrew.status.collect import (
    linker_produced_match as linker_produced_match,
)
from rebrew.status.collect import (
    load_verify_details as load_verify_details,
)
from rebrew.status.collect import (
    load_verify_statuses as load_verify_statuses,
)
from rebrew.status.collect import (
    native_tail_span as native_tail_span,
)
from rebrew.status.collect import (
    postlink_copied_ranges as postlink_copied_ranges,
)
from rebrew.status.collect import (
    span_is_copied as span_is_copied,
)
from rebrew.status.render import (
    render_terminal as render_terminal,
)
lazy from rebrew.config import ProjectConfig as ProjectConfig
lazy from rebrew.formats.binary_model import BinaryInfo as BinaryInfo
lazy from rebrew.source.discovery import iter_sources as iter_sources

# Local private aliases preserved for existing test imports and monkeypatches.
_attach_file_similarity = attach_file_similarity
_load_cache_raw = load_cache_raw
_load_verify_info = load_verify_info
_compute_text_size = compute_text_size
_target_binary = target_binary
_initialized_data_ranges = initialized_data_ranges
_render_terminal = render_terminal

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  rebrew status  # Quick project overview\n\n"
    "  rebrew status --json  # Machine-readable JSON output\n\n"
    "  rebrew status --target client_exe  # Status for a specific target\n\n"
    "[dim]Reads source bindings, metadata, and function structure (no compilation needed). "
    "Run 'rebrew verify' first for verify stats, or 'rebrew coverage catalog' for function data.[/dim]"
)

app = typer.Typer(
    help="At-a-glance reversing progress overview.",
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


@app.callback(invoke_without_command=True)
def main(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Show reversing progress overview for the current project."""
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(json_output=json_output, target=n, all_targets=False),
    ):
        return
    from rebrew.compiler.cache import include_closure_cache
    from rebrew.formats.binary_loader import cache_pe_layouts

    with cache_pe_layouts():
        cfg = require_config(target=target, json_mode=json_output)
        with include_closure_cache(cfg.root / ".rebrew" / "include-closures.json"):
            report = collect_status(cfg)

    if json_output:
        json_print(report.to_dict())
        return

    _render_terminal(report)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
