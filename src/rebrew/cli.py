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

from typing import Any

import typer

from rebrew.config import ProjectConfig, load_config

# Re-usable Typer option for --target
TargetOption: str | None = typer.Option(
    None,
    "--target",
    "-t",
    help="Target name from rebrew.toml (default: first target).",
)


def get_config(target: str | None = None) -> ProjectConfig:
    """Load the project config for the given target."""
    return load_config(target=target)


def source_glob(cfg: Any) -> str:
    """Return glob pattern for source files based on the configured extension.

    Uses ``cfg.source_ext`` (e.g. ``".c"``, ``".cpp"``) to build a pattern
    like ``"*.c"`` or ``"*.cpp"``.  Falls back to ``"*.c"`` if the attribute
    is missing.
    """
    ext = getattr(cfg, "source_ext", ".c")
    return f"*{ext}"
