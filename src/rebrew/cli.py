"""Shared CLI utilities for rebrew tools.

Provides common Typer options and config-loading helpers so that every
tool gets ``--target`` support without boilerplate.

Usage in a tool::

    import typer
    from rebrew.cli import TargetOption, get_config

    app = typer.Typer()

    @app.command()
    def main(target: str = TargetOption):
        cfg = get_config(target)
        ...
"""

from __future__ import annotations

from typing import Optional

import typer

from rebrew.config import ProjectConfig, load_config

# Re-usable Typer option for --target
TargetOption: Optional[str] = typer.Option(
    None,
    "--target",
    "-t",
    help="Target name from rebrew.toml (default: first target).",
)


def get_config(target: Optional[str] = None) -> ProjectConfig:
    """Load the project config for the given target."""
    return load_config(target=target)
