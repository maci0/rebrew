"""`rebrew schema`: the clispec 0.3 document, with no project and no network."""

from __future__ import annotations

import typer

app = typer.Typer(
    help="Print the clispec 0.3 JSON document for this CLI.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew schema\n\n"
        "  rebrew schema skills list\n\n"
        "The document is JSON on stdout. It does not read a project, a credential, or the network.\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    command: list[str] = typer.Argument(
        None,
        help="Command path to include. Matching commands and their children are kept.",
    ),
) -> None:
    """Print the clispec 0.3 JSON document for this CLI."""
    from rebrew.app.main import app as root
    from rebrew.cli import error_exit, json_print
    from rebrew.clispec import build_schema

    path = " ".join(command or [])
    document = build_schema(root, path=path or None)
    if path and not document["commands"]:
        error_exit(
            f"no command matches {path!r}",
            json_mode=True,
            kind="usage",
            hint="Run rebrew schema with no path to list every command.",
        )
    json_print(document)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)
