"""Review all-target source organization and compare raw rebuild artifacts."""

lazy from pathlib import Path

import typer

lazy from rebrew.cli import (
    EXPECTED_DIGEST_HELP,
    console,
    error_exit,
    json_print,
    require_config,
    run_cli,
)
lazy from rebrew.config import ProjectConfig
lazy from rebrew.source_organization import (
    check_reorganization,
    organization_configs,
    review_organization,
)

app = typer.Typer(
    help="Review target providers, TU contexts and native orders before reorganizing source.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew source organize review src/a.c src/b.c --json\n\n"
        "  rebrew source organize check old-raw.dll build/raw.dll --json\n\n"
        "Reviews are read-only. Rebuild every affected target and compare raw links."
    ),
)


def _review_configs(cfg: ProjectConfig) -> list[ProjectConfig]:
    from rebrew.metadata.coordinated import path_identity_digest

    path = cfg.root / "rebrew-project.toml"
    before = (path.read_bytes() if path.is_file() else None, path_identity_digest(path))
    configs = organization_configs(cfg)
    if (path.read_bytes() if path.is_file() else None, path_identity_digest(path)) != before:
        raise ValueError("project config changed while loading targets")
    selected = [item for item in configs if item.target_name == cfg.target_name]
    if cfg.target_name and (not selected or selected[0].as_dict() != cfg.as_dict()):
        raise ValueError("target configuration is stale; reload before review")
    return configs


@app.command(
    "review",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source organize review a.c b.c --destination merged.c --json",
)
def review_cmd(
    files: list[Path] = typer.Argument(
        ..., help="Existing project sources to review across every target"
    ),
    destination: Path | None = typer.Option(
        None,
        "--destination",
        help="Proposed merged TU; checks foreign-definition and compiler-setting changes",
    ),
    shared: bool = typer.Option(
        False, "--shared", help="Model same-named identical definitions as shared merge candidates"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Preview providers, original compilation contexts and conflicting native orders."""
    cfg = require_config(json_mode=json_output)
    try:
        report = review_organization(
            _review_configs(cfg),
            [path.resolve() for path in files],
            destination=destination.resolve() if destination is not None else None,
            shared=shared,
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if report["problems"] or report["unknown"]:
        raise typer.Exit(1)


@app.command(
    "guards",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source organize guards a.c b.c --json",
)
def guards_cmd(
    files: list[Path] = typer.Argument(..., help="Existing project sources to inspect"),
    expected_digest: str | None = typer.Option(
        None, "--expected-digest", help=EXPECTED_DIGEST_HELP
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Review exact conditional contexts and conflicting declarations without rewriting."""
    from rebrew.source_guard_context import guard_contexts

    cfg = require_config(json_mode=json_output)
    try:
        paths = [path.resolve() for path in files]
        review = review_organization(_review_configs(cfg), paths)
        if expected_digest is not None and expected_digest != review["input_digest"]:
            raise ValueError("organization inputs changed; review a new plan")
        report = guard_contexts(paths)
        # Detect changes between the organization digest and exact-source read.
        after = review_organization(_review_configs(cfg), paths)
        if review["input_digest"] != after["input_digest"]:
            raise ValueError("organization inputs changed during guard inspection")
        report.update(
            input_digest=review["input_digest"],
            unknown=review["unknown"],
            problems=review["problems"],
        )
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if report["declaration_conflicts"] or report["problems"] or report["unknown"]:
        raise typer.Exit(1)


@app.command(
    "check",
    epilog="[bold]Examples:[/bold]\n\n  rebrew source organize check old-raw.dll build/raw.dll --json",
)
def check_cmd(
    before: Path = typer.Argument(..., help="Preserved raw link before the source reorganization"),
    after: Path = typer.Argument(..., help="Fresh raw rebuild after the source reorganization"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compare complete PE raw links, code/data bytes and section placement."""
    try:
        report = check_reorganization(before, after)
    except (OSError, ValueError) as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print(report)
    else:
        console.print(report)
    if not report["match"]:
        raise typer.Exit(1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_cli(app)


if __name__ == "__main__":
    main_entry()
