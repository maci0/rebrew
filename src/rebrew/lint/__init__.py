"""Validate source bindings, dedicated metadata, and C source conventions.

Identity, kind and state live in metadata; optional ADDRESS comments anchor the
next definition or variable declaration. Legacy inline state is rejected. Check
native function boundaries (W028), redundant compiler flags (W029), data extents
and ownership. Fixes update dedicated metadata through its locked writers.
"""

from collections import Counter
from pathlib import Path
lazy import bisect
lazy import contextlib
lazy import logging
lazy import unicodedata
lazy from typing import Any

import typer
lazy from rich.text import Text

from rebrew.cli import (
    EXIT_MISMATCH,
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
)
from rebrew.lint.metadata_rules import (
    LintResult as LintResult,
)
from rebrew.lint.metadata_rules import (
    MissingSection as MissingSection,
)
from rebrew.lint.metadata_rules import (
    check_E001_kind,
    check_E002_va,
    check_E013_duplicate_va,
    check_E015_kind_consistency,
    check_W005_blocker,
    check_W015_va_case,
    check_W018_cflags,
    check_W031_metadata_store,
    check_W031_source_provenance,
    check_W031_type_metadata,
    check_W033_agent_scaffold,
    check_W034_identity_paths,
    check_W035_unknown_modules,
    check_W036_stray_metadata_store,
    check_W038_data_row_overlap,
)
from rebrew.lint.source_rules import (
    build_function_index as build_function_index,
)
from rebrew.lint.source_rules import (
    lint_file as lint_file_core,
)
from rebrew.lint.source_rules import (
    retired_leftover,
    source_headers,
    strip_c_comments_strings,
)
from rebrew.metadata.bindings import SourceBinding as SourceBinding
lazy from rebrew.config import ProjectConfig, load_config
lazy from rebrew.lint_cflags import (
    RedundantFunctionCflags,
    RedundantPreset,
    drop_redundant_presets,
)
lazy from rebrew.lint_cflags import (
    check_redundant_cflags as check_redundant_cflags,
)
lazy from rebrew.metadata.data import load_data_metadata
lazy from rebrew.metadata.functions import load_metadata
lazy from rebrew.source.discovery import iter_sources, source_exts
lazy from rebrew.utils import TerminalTable, untrusted_ident

log = logging.getLogger(__name__)

# Local `_`-aliases retained for test compatibility (never imported across modules).
_check_E001_kind = check_E001_kind  # noqa: N816
_check_E002_va = check_E002_va  # noqa: N816
_check_E013_duplicate_va = check_E013_duplicate_va  # noqa: N816
_check_E015_kind_consistency = check_E015_kind_consistency  # noqa: N816
_check_W005_blocker = check_W005_blocker  # noqa: N816
_check_W015_va_case = check_W015_va_case  # noqa: N816
_check_W018_cflags = check_W018_cflags  # noqa: N816
_check_W031_metadata_store = check_W031_metadata_store  # noqa: N816
_check_W031_source_provenance = check_W031_source_provenance  # noqa: N816
_check_W031_type_metadata = check_W031_type_metadata  # noqa: N816
_check_W034_identity_paths = check_W034_identity_paths  # noqa: N816
_check_W035_unknown_modules = check_W035_unknown_modules  # noqa: N816
_check_W036_stray_metadata_store = check_W036_stray_metadata_store  # noqa: N816
_check_W038_data_row_overlap = check_W038_data_row_overlap  # noqa: N816
_retired_leftover = retired_leftover
_source_headers = source_headers
_strip_c_comments_strings = strip_c_comments_strings


def _check_W033_agent_scaffold(cfg: ProjectConfig) -> list[LintResult]:
    from rebrew.init import agent_skill_files

    return check_W033_agent_scaffold(cfg, skill_files_fn=agent_skill_files)


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    *,
    seen_vas: dict[Any, str] | None = None,
    seen_va_defines: dict[Any, bool] | None = None,
    seen_globals: dict[str, tuple[str, int, bool]] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_historical_sources: set[Path] | None = None,
    preloaded_source_files: frozenset[str] | None = None,
    metadata_directory: Path | None = None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None = None,
    pedantic: bool = False,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> LintResult:
    """Lint a single C file."""
    return lint_file_core(
        filepath,
        cfg=cfg,
        seen_vas=seen_vas,
        seen_va_defines=seen_va_defines,
        seen_globals=seen_globals,
        preloaded_metadata=preloaded_metadata,
        preloaded_data_metadata=preloaded_data_metadata,
        preloaded_historical_sources=preloaded_historical_sources,
        preloaded_source_files=preloaded_source_files,
        metadata_directory=metadata_directory,
        function_index=function_index,
        pedantic=pedantic,
        section_for_va=section_for_va,
        section_hits=section_hits,
        strip_line=_strip_c_comments_strings,
        retired_leftover_fn=_retired_leftover,
    )


def _print_summary(results: list[LintResult]) -> None:
    """Print a breakdown table by status and binding kind.

    Uses counters collected during the lint pass (LintResult._status_counts
    and _kind_counts) instead of re-reading every file.
    """
    status_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    for r in results:
        status_counts += r._status_counts
        kind_counts += r._kind_counts

    console.print()
    table = TerminalTable(title="Summary", show_lines=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right", width=8, no_wrap=True)

    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        table.add_row("STATUS", untrusted_ident(status), str(count))
    for kind, count in sorted(kind_counts.items(), key=lambda x: -x[1]):
        table.add_row("KIND", kind, str(count))

    console.print(table)


app = typer.Typer(
    help="Check C source bindings, metadata, and project conventions.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew lint\n\n"
        "  rebrew lint src/game/foo.c --quiet\n\n"
        "  rebrew lint --summary\n\n"
        "  rebrew lint --fix --dry-run\n\n"
        "  rebrew lint --json\n\n"
        "[dim]Checks C bindings, dedicated metadata, compiler flags, project style, storage declarations, and scaffold drift. Optional ADDRESS comments bind the next definition; all identity/state stays in format-3 function metadata and format-2 data metadata. Unsupported inline state is diagnosed, not migrated.[/dim]\n\n"
        "[bold]Fixes:[/bold]\n\n"
        "  --fix removes redundant compiler flags and backfills known SECTION metadata. Preview with --dry-run; other findings require review.\n\n"
        "[bold]Common findings:[/bold]\n\n"
        "  E001: missing metadata identity or support purpose; E013: duplicate VA.\n\n"
        "  E023: whole-function naked assembly instead of reconstructed C.\n\n"
        "  W005: STUB without BLOCKER; W016: data without SECTION metadata.\n\n"
        "  E024: unsupported inline state; W028: bound VA absent from function inventory.\n\n"
        "  W029: redundant flags; W031: metadata schema/provenance problem.\n\n"
        "  W033-W035: scaffold, file identity, or module drift.\n\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(
        False,
        "--fix",
        help=("Remove redundant compiler flags and backfill SECTION metadata (W016)"),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show errors, suppress warnings"),
    pedantic: bool = typer.Option(
        False,
        "--pedantic",
        help="Warn on functions that have not been renamed yet to a meaningful name",
    ),
    files: list[Path] | None = typer.Argument(
        None, help="Specific files to check (defaults to all *.c in project)"
    ),
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Check C source bindings, metadata, and project conventions."""
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            fix=fix,
            dry_run=dry_run,
            quiet=quiet,
            pedantic=pedantic,
            files=files,
            summary=summary,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    # `load_config`, not `require_config`: naming files explicitly lints them
    # without a project (config-aware rules off).  Bare `rebrew lint` has no
    # such fallback — see the `reversed_dir` branch below.
    cfg = None
    no_config = False
    try:
        cfg = load_config(target=target)
    except FileNotFoundError:
        no_config = True
    except (KeyError, ValueError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] config error ({untrusted_ident(exc)}); "
            "config-aware rules disabled"
        )

    reversed_dir = cfg.reversed_dir if cfg else None

    exts = source_exts(cfg)
    if files:
        # `source_ext` may hold several comma-separated extensions; comparing
        # the raw string against `f.suffix` matched nothing, so `rebrew lint
        # foo.cpp` with `source_ext = ".c,.cpp"` silently checked 0 files.
        # Both sides are lowercased: `parse_source_ext` keeps the configured
        # spelling, and `iter_sources` matches suffixes case-insensitively
        # (sources.files_with_ext), so `rebrew lint FOO.C` with
        # `source_ext = ".C"` must find the same file as a bare run.
        lowered = {ext.lower() for ext in exts}
        c_files = [f for f in files if f.suffix.lower() in lowered]
    elif reversed_dir:
        c_files = iter_sources(reversed_dir, cfg)
    elif no_config:
        # No project and no file list: the only thing left to guess is "every
        # C file under the cwd", which lints vendored trees (.venv, build/)
        # and reports their findings as the project's.  Exit 2 like every
        # other command that cannot find a project, naming both ways out.
        error_exit(
            "no rebrew-project.toml found and no files given. "
            "Run 'rebrew lint' from inside a project, or pass the files to "
            "check explicitly (rebrew lint path/to/file.c).",
            json_mode=json_output,
        )
    else:
        c_files = sorted({p for ext in exts for p in Path.cwd().rglob(f"*{ext}")})

    # Cross-file duplicate tracking: VAs (E013) and global names (W021).
    # seen_vas keys are (module, va) tuples — bare int would falsely flag
    # cross-module files that legitimately share a VA in different targets.
    seen_vas: dict[Any, str] = {}
    seen_va_defines: dict[Any, bool] = {}
    seen_globals: dict[str, tuple[str, int, bool]] = {}

    metadata_directory = cfg.metadata_dir if cfg is not None else None
    # Pre-load metadata once for the whole batch (avoids per-file I/O).
    _preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    _preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    if cfg:
        _preloaded_metadata = load_metadata(metadata_directory, deepcopy=False)
        _preloaded_data_metadata = load_data_metadata(metadata_directory, deepcopy=False)
    historical_sources: set[Path] | None = None
    source_files: frozenset[str] | None = None
    if cfg is not None:
        from rebrew.metadata.binding_history import historical_source_files
        from rebrew.metadata.source_provenance import load_source_files

        assert metadata_directory is not None
        historical_sources = {
            path
            for row in (_preloaded_metadata or {}).values()
            if row.get("binding_history", []) != []
            for path in historical_source_files(row, metadata_directory, cfg.root)
        }
        # One store read for the batch. Loading it per file made lint stat and
        # glob the whole metadata collection once per source (`--fix` and the
        # plain check share this path).
        source_files = frozenset(record.file for record in load_source_files(metadata_directory))
    # Pre-load the function list once for the whole batch (W028).
    function_index = build_function_index(cfg) if cfg else None
    # Section resolver for W016 autofix (DATA/GLOBAL bindings missing SECTION):
    # one binary parse per batch, mapping VA -> section name.  The load is
    # deferred to the first VA actually queried: a run without a SECTION-less
    # DATA/GLOBAL binding never pays LIEF's ~0.13 s import, and an unusable
    # binary just leaves the resolver returning "" (W016 stays warn-only).
    section_for_va: Any = None
    if cfg is not None and getattr(cfg, "target_binary", None):
        _bin_path = cfg.target_binary
        _loaded = False
        _ranges: list[tuple[int, int, str]] = []
        _starts: list[int] = []

        def section_for_va(va: int) -> str:
            nonlocal _loaded, _ranges, _starts
            if not _loaded:
                _loaded = True  # an unusable binary must not retry per VA
                try:
                    from rebrew.formats.binary_loader import load_binary

                    _info = load_binary(_bin_path)
                    _ranges = sorted(
                        ((s.va, s.va + s.size, s.name) for s in _info.sections.values()),
                        key=lambda t: t[0],
                    )
                    _starts = [r[0] for r in _ranges]
                except Exception as exc:
                    # W016 stays warn-only; record why every VA resolves to no section.
                    log.debug("W016 section lookup disabled: %s cannot be read: %s", _bin_path, exc)
                    _ranges = []
                    _starts = []
            idx = bisect.bisect_right(_starts, va) - 1
            # A shorter section nested in a longer one must not hide the outer tail.
            while idx >= 0:
                start, end, name = _ranges[idx]
                if start <= va < end:
                    return name
                idx -= 1
            return ""

    section_hits: list[MissingSection] = []

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0
    all_results: list[LintResult] = []

    display_buf: list[str] = []
    for cfile in c_files:
        total += 1
        result = lint_file(
            cfile,
            cfg=cfg,
            seen_vas=seen_vas,
            seen_va_defines=seen_va_defines,
            seen_globals=seen_globals,
            preloaded_metadata=_preloaded_metadata,
            preloaded_data_metadata=_preloaded_data_metadata,
            preloaded_historical_sources=historical_sources,
            preloaded_source_files=source_files,
            metadata_directory=metadata_directory,
            function_index=function_index,
            pedantic=pedantic,
            section_for_va=section_for_va,
            section_hits=section_hits,
        )
        all_results.append(result)
        if result.passed:
            passed += 1
        if not json_output and (not result.passed or (not quiet and result.warnings)):
            display_buf.extend(result.display_lines(quiet))
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    if display_buf:
        # One Rich print for the whole batch: nothing else prints during the
        # loop, so the output bytes are identical — one markup+wrap pass
        # instead of ~400 per-file envelopes (the largest remaining lint
        # cost after the W029 batching).
        console.print("\n".join(display_buf), highlight=False)

    # W029: redundant cflags across metadata + presets — batch-level, since
    # no single .c file owns a preset and the redundancy is about the fallback
    # ladder.  Attribute per-function warnings back to the file that hosts the
    # VA when possible; presets and unattributed VAs land on a synthetic entry.
    preset_redundant: list[RedundantPreset] = []
    fn_redundant: list[RedundantFunctionCflags] = []
    if cfg is not None:
        preset_redundant, fn_redundant = check_redundant_cflags(cfg, _preloaded_metadata)
        if preset_redundant or fn_redundant:
            # Build VA -> file index from this run, for per-function attribution.
            # LintResult.binding_line holds the LAST binding in the file, so
            # the header's own line travels with the index.
            va_to_result: dict[tuple[str, int], tuple[LintResult, int]] = {}
            for r in all_results:
                headers = r._headers if r._headers is not None else _source_headers(r._lines)
                for keys, _flags in headers:
                    m = keys.get("MODULE", "")
                    v = keys.get("VA", "")
                    if not m or not v:
                        continue
                    with contextlib.suppress(ValueError):
                        va_to_result[(m, int(v, 16))] = (r, int(keys.get("_LINE", "1")))
            # Presets: no single file — emit on a synthetic "config" result.
            if preset_redundant:
                syn = LintResult(Path("rebrew-project.toml"))
                for hit in preset_redundant:
                    syn.warning(1, "W029", f"redundant cflags preset: {hit.message()}")
                all_results.append(syn)
                if not json_output and not quiet:
                    syn.display(quiet=False)
                warning_count += len(syn.warnings)
            # Per-function redundancies: attribute per file when we can.
            unattributed: list[RedundantFunctionCflags] = []
            w029_inline: list[str] = []
            for fn_hit in fn_redundant:
                located = va_to_result.get((fn_hit.module, fn_hit.va))
                msg = fn_hit.message()
                if located is not None:
                    dest, line = located
                    if not any(c == "W029" and msg in m for _, c, m in dest.warnings):
                        dest.warning(line, "W029", f"redundant cflags: {msg}")
                        warning_count += 1
                        if not json_output and not quiet:
                            # Show the newly added warnings inline (the batch
                            # loop already printed these files) — collected
                            # and emitted as ONE Rich print below: per-hit
                            # prints were 1600 console calls on a
                            # 400-file tree, ~27% of lint's runtime.
                            w029_inline.append(
                                f"  [bold]{untrusted_ident(dest.filepath.name)}[/bold]:{line}: "
                                f"[yellow]W029[/yellow]: redundant cflags: "
                                f"{untrusted_ident(msg)}"
                            )
                else:
                    unattributed.append(fn_hit)
            if w029_inline:
                console.print("\n".join(w029_inline), highlight=False)
            if unattributed:
                syn2 = LintResult(Path("rebrew-functions.toml"))
                for fn_hit in unattributed:
                    syn2.warning(1, "W029", f"redundant cflags: {fn_hit.message()}")
                all_results.append(syn2)
                if not json_output and not quiet:
                    syn2.display(quiet=False)
                warning_count += len(syn2.warnings)

    # W031, W033-W038: the same batch-level shape as W029 — no .c file owns the
    # metadata store or the scaffold, so each finding lands on the artifact it
    # describes and the per-file loop stays untouched.
    if cfg is not None:
        for artifact_result in (
            *_check_W031_metadata_store(cfg),
            *_check_W031_source_provenance(cfg),
            *_check_W031_type_metadata(cfg),
            *_check_W036_stray_metadata_store(cfg),
            *_check_W034_identity_paths(cfg),
            *_check_W035_unknown_modules(cfg),
            *_check_W038_data_row_overlap(cfg),
            *_check_W033_agent_scaffold(cfg),
        ):
            all_results.append(artifact_result)
            warning_count += len(artifact_result.warnings)
            if not json_output and not quiet:
                artifact_result.display(quiet=False)

    if json_output:
        # --quiet keeps the counts but lists only failing files, without
        # their warnings (docs: "Suppress warnings, show errors only").
        files_out = [r.to_dict() for r in all_results if not r.passed or (r.warnings and not quiet)]
        if quiet:
            for entry in files_out:
                entry["warnings"] = []
        output = {
            "total": total,
            "passed": passed,
            "errors": error_count,
            "warnings": warning_count,
            "files": files_out,
        }
        json_print(output)
    else:
        pass_style = "green" if error_count == 0 else "red"
        err_style = "red" if error_count > 0 else ""
        result_text = Text()
        result_text.append(f"\nChecked {total} files: ")
        result_text.append(f"{passed} passed", style=pass_style)
        result_text.append(", ")
        result_text.append(f"{error_count} errors", style=err_style)
        result_text.append(f", {warning_count} warnings")
        console.print(result_text)

        if summary:
            _print_summary(all_results)

    # Fixes write dedicated metadata through its locked writers.
    if fix and not cfg:
        console.print(
            "[yellow]warning:[/yellow] --fix needs a rebrew-project.toml — "
            "no config loaded, no metadata updated"
        )
    if fix and cfg:
        from rebrew.metadata.data import set_data_fields_batch
        from rebrew.metadata.functions import remove_fields_batch

        w029_fn_count = 0
        if fn_redundant:
            if dry_run:
                for fn_hit in fn_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant cflags "
                        f"{untrusted_ident(fn_hit.module)} 0x{fn_hit.va:x} "
                        f"(inherited {fn_hit.inherited!r})"
                    )
                w029_fn_count = len(fn_redundant)
            else:
                w029_fn_count = remove_fields_batch(
                    metadata_directory,
                    [
                        {"module": fn_hit.module, "va": fn_hit.va, "keys": ["cflags"]}
                        for fn_hit in fn_redundant
                    ],
                )
        w029_preset_count = 0
        if preset_redundant:
            if dry_run:
                for preset_hit in preset_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant preset "
                        f"cflags_presets.{untrusted_ident(preset_hit.module)}"
                    )
            w029_preset_count = drop_redundant_presets(cfg, preset_redundant, dry_run=dry_run)
            if dry_run and w029_preset_count == 0:
                w029_preset_count = len(preset_redundant)

        section_count = 0
        if section_hits:
            if dry_run:
                for section_hit in section_hits:
                    console.print(
                        f"  [dim]Would set[/dim] section {section_hit.section!r} "
                        f"for {untrusted_ident(section_hit.module)} "
                        f"0x{section_hit.va:x} (rebrew-data.toml)"
                    )
                section_count = len(section_hits)
            else:
                # One rebrew-data.toml rewrite for all hits, not one per symbol.
                section_updates: dict[tuple[str, int], dict[str, Any]] = {}
                for section_hit in section_hits:
                    hit_key = (section_hit.module, section_hit.va)
                    if hit_key in section_updates:
                        continue
                    # The batch already loaded this table. Reusing its row
                    # avoids a path resolve, store fingerprint and deepcopy per
                    # SECTION backfill.
                    existing = (_preloaded_data_metadata or {}).get(
                        (unicodedata.normalize("NFC", section_hit.module), section_hit.va), {}
                    )
                    if "section" in {k.lower() for k in existing}:
                        continue
                    section_updates[hit_key] = {
                        "module": section_hit.module,
                        "va": section_hit.va,
                        "fields": {"section": section_hit.section},
                        "updated_by": "lint",
                    }
                set_data_fields_batch(metadata_directory, list(section_updates.values()))
                section_count = len(section_updates)

        if not json_output:
            parts: list[str] = []
            if dry_run:
                if w029_fn_count:
                    parts.append(f"{w029_fn_count} redundant per-function cflags would be dropped")
                if w029_preset_count:
                    parts.append(f"{w029_preset_count} redundant cflags presets would be dropped")
                if section_count:
                    parts.append(f"{section_count} missing SECTIONs would be backfilled")
                if parts:
                    console.print(f"\n[yellow]Dry run:[/yellow] {'; '.join(parts)}")
            else:
                if w029_fn_count:
                    parts.append(f"dropped {w029_fn_count} redundant per-function cflags")
                if w029_preset_count:
                    parts.append(f"dropped {w029_preset_count} redundant cflags presets")
                if section_count:
                    parts.append(f"backfilled {section_count} missing SECTIONs")
                if parts:
                    console.print(f"\n[green]Fixed:[/green] {'; '.join(parts)}")

    if error_count > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
